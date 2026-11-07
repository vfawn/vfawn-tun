// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The in-house stack as a `StackBackend`: the TCP state machine from
//! `native_tcp` riding the shard skeleton, sessions handed to the host
//! through the same contract the ipstack backend uses.
//!
//! Each flow's shard slot owns one `ServerConnection` and a channel
//! pair: bytes the connection delivers flow to the host through
//! `HostEvent`s, bytes the host writes flow back through a shared
//! inbox the shard drains after each packet batch. The state machine
//! stays pure (no I/O, no threads), the shard loop keeps sole
//! ownership of the connection table, and this file is the only place
//! that knows both.
//!
//! The slot is where three policy layers attach: the
//! host's verdict on the flow's first segment (a rejected flow is
//! answered with a real RST, the debt the transitional backend could
//! not pay because it never saw the SYN's bytes), the accept layer's
//! choice of ISN (a SYN cookie in cookie mode, a backlog bound in
//! the other), and a congestion controller whose window bounds how
//! much unacknowledged data the write drain may put on the wire.
//!
//! Honesty ledger: the session reaches the host only once the
//! handshake completes, so a spoofed SYN costs a shard slot and
//! nothing else; loss signals (timeout, fast retransmit) cannot fire
//! in production yet because retransmission timers ride the shard
//! timer heap, which is the next wiring, so today the window only
//! grows and gates.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bytes::BytesMut;

use vfawn_core::{
    FlowInfo, Network, PacketDevice, SessionHandler, StackBackend, StackHandle, TcpSession,
    TcpTransport, Verdict,
};
use vfawn_wire::emit::tcp_rst_v4;
use vfawn_wire::flow::FlowKey;
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::protocol::IpProtocol;
use vfawn_wire::tcp::TcpHeader;

use crate::accept::{AcceptQueue, FixedSecret};
use crate::congestion::{CongestionAlgo, Cubic, Reno, Signal};
use crate::native_tcp::{Inbound, Reaction, ServerConnection, TcpState, ctl, emit_tcp};
use crate::shards::{BufferPool, LogicFactory, ShardBell, ShardConfig, Shards, SlotLogic};
use vfawn_wire::emit::tcp_rst_v6;

/// The fallback segment size when the backend is constructed without
/// one: RFC 9293 §3.7.1's default for a peer that sent no MSS option.
/// A real deployment derives it from the device's MTU instead.
const DEFAULT_MSS: u16 = 536;

/// What a slot tells the session wrapper.
enum HostEvent {
    Established,
    Bytes(Vec<u8>),
    Closed,
}

/// The v4 endpoints of a flow, as the emitter wants them.
fn v4_ends(flow: &FlowKey) -> Option<(std::net::SocketAddr, std::net::SocketAddr)> {
    Some((
        std::net::SocketAddr::new(flow.src, flow.src_port),
        std::net::SocketAddr::new(flow.dst, flow.dst_port),
    ))
}

/// The host's outbound queue for one flow, bounded in bytes: a host
/// that writes faster than the wire carries (a relay pumping from a
/// memory-speed socket) must feel backpressure, or the queue becomes
/// the process's memory ceiling.
struct WriteLane {
    writes: VecDeque<Vec<u8>>,
    bytes: usize,
}

/// How much unsent host output one flow may hold. A few windows'
/// worth keeps the pipe full; the bound keeps ten thousand flows
/// from owing the process gigabytes.
const LANE_CAP: usize = 256 * 1024;

impl WriteLane {
    fn new() -> Self {
        Self {
            writes: VecDeque::new(),
            bytes: 0,
        }
    }
}

/// One flow inside a shard: the connection, the congestion controller
/// that bounds its send side, and the host lane that earns a channel
/// only when the handshake completes.
struct TcpSlot {
    connection: ServerConnection,
    client: std::net::SocketAddr,
    server: std::net::SocketAddr,
    handler: Arc<dyn SessionHandler>,
    accept: Arc<std::sync::Mutex<AcceptQueue>>,
    sessions: mpsc::SyncSender<SessionHandoff>,
    flow: FlowInfo,
    /// The lane this slot's host writes arrive on.
    write_lane: Arc<std::sync::Mutex<WriteLane>>,
    /// The shard's doorbell this slot's lane rings on host writes.
    shard_wake: Arc<ShardBell>,
    cc: Box<dyn CongestionAlgo>,
    /// The host channel, created when the handshake completes. A SYN
    /// that never completes (a spoofed flood) costs nothing here.
    to_host: Option<tokio::sync::mpsc::UnboundedSender<HostEvent>>,
    /// The host verdict runs once, on the flow's first segment.
    judged: bool,
    /// A rejected or dropped flow: everything after is swallowed.
    refused: bool,
    /// Unacknowledged sent bytes, contiguous from `flight_base`
    /// (RFC 9293 §3.3.1's send buffer): what a retransmission owes.
    flight: Vec<u8>,
    flight_base: u32,
    data_sent_at: Option<Instant>,
    data_retries: u32,
    /// The SYN-ACK's clock while the handshake waits (RFC 9293 §3.4).
    synack_at: Option<Instant>,
    synack_retries: u32,
    /// Our FIN's sequence while LAST-ACK waits for its acknowledgment.
    fin_at: Option<u32>,
    /// The zero-window persist clock (RFC 9293 §3.8.2): when the peer
    /// advertised nothing and output is waiting, only our probe can
    /// learn whether the window reopened — the peer, believing its
    /// side healthy, owes us no packet that would tell us.
    persist_at: Option<Instant>,
    persist_retries: u32,
    /// Rate limit for the stalled-drain alarm below.
    diag_at: Option<Instant>,
    /// The queue depth the last alarm saw: a real stall holds the
    /// same depth a second later, while a healthy trickle moves.
    diag_queued: usize,
    /// The keepalive clock: when the next probe is due. None while
    /// the connection is active; armed on the idle sweep.
    keepalive_at: Option<Instant>,
    /// Probes sent without an answer since the last activity.
    keepalive_probes: u32,
    /// The flow's dispatch key, for the splice lane's lookup.
    flow_key: vfawn_wire::flow::FlowKey,
    /// The tracker the host's verdict attached, handed to the session
    /// when the handshake completes.
    tracker: Option<Arc<dyn vfawn_core::FlowTrackerHook>>,
}

/// The first retransmission timeout and its ceiling (RFC 6298 §2's
/// bounds, taken to the local-link scale this stack serves: a floor of
/// one second would leave a stalled control connection mute for ages).
const RTO_BASE: Duration = Duration::from_millis(200);
const RTO_CEIL: Duration = Duration::from_secs(2);

/// The backoff for a retry count (RFC 6298 §5: doubling per attempt).
fn rto_backoff(retries: u32) -> Duration {
    let shift = retries.min(4);
    let scaled = RTO_BASE.saturating_mul(1u32 << shift);
    scaled.min(RTO_CEIL)
}

/// How many times the handshake's answer is repeated before the flow
/// is written off, and how many times unacknowledged data is repeated
/// before the connection is pronounced dead. Dead connections tell the
/// host and go inert, which is also the only reaping a vanished peer
/// gets in this volume.
const SYNACK_RETRY_MAX: u32 = 5;
const DATA_RETRY_MAX: u32 = 15;
/// How many persist probes a closed window gets before the flow is
/// written off. A window that never reopens while output waits is a
/// peer that will not read us again; the probes back off alongside
/// the retransmission timer and the give-up resets the peer.
const PERSIST_RETRY_MAX: u32 = 12;
/// How long an ESTABLISHED flow may sit idle before the first
/// keepalive probe (RFC 9293 §3.8.1). The interval and probe budget
/// share the estimate: three probes ten seconds apart catches a
/// vanished peer inside half a minute of the first question.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_PROBE_MAX: u32 = 3;

impl TcpSlot {
    fn announce(&mut self) {
        if self.to_host.is_some() || self.connection.state() != TcpState::Established {
            return;
        }
        // The handshake completed; only now does the flow earn a
        // session. This is the accept layer's other half: state that
        // never establishes (the spoofed SYN's slot) never reaches the
        // host, never allocates channels, never spawns a task.
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
        let handoff = SessionHandoff {
            flow: self.flow.clone(),
            events: event_rx,
            write_lane: Arc::clone(&self.write_lane),
            shard_wake: Arc::clone(&self.shard_wake),
            tracker: self.tracker.take(),
        };
        if self.sessions.send(handoff).is_ok() {
            let _ = event_tx.send(HostEvent::Established);
            self.to_host = Some(event_tx);
            self.accept
                .lock()
                .expect("accept lock")
                .on_established(self.flow.source);
        }
    }

    /// The host's verdict on the first segment, with the same panic
    /// containment as the transitional backend: a panicking judge costs
    /// its own flow, never the shard. The contract sends no SYN bytes
    /// (`judge_flow`'s first packet is a payload for UDP only); the
    /// raw segment stays available for the RST the reject path owes.
    fn judge(&mut self, packet: &[u8], out: &mut VecDeque<BytesMut>) {
        self.judged = true;
        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.handler.judge_flow(&self.flow, &[])
        }))
        .unwrap_or(Verdict::Drop);
        match vfawn_core::verdict::execute(verdict, &self.flow) {
            vfawn_core::verdict::VerdictAction::CreateSession { tracker, .. } => {
                self.tracker = tracker.map(|hook| hook as Arc<dyn vfawn_core::FlowTrackerHook>);
            }
            vfawn_core::verdict::VerdictAction::Reset => {
                // The debt the transitional backend could not pay: the
                // raw SYN is right here, so the RST is real (RFC 9293
                // §3.4, constructed from the offending segment).
                let reset = match self.server.ip() {
                    std::net::IpAddr::V4(server) => tcp_rst_v4(packet, server),
                    std::net::IpAddr::V6(server) => tcp_rst_v6(packet, server),
                };
                if let Some(frame) = reset {
                    out.push_back(BytesMut::from(&frame[..]));
                }
                self.refused = true;
            }
            _ => self.refused = true,
        }
    }

    /// Move host-written backlog bytes into segments, never letting
    /// what is unacknowledged exceed the congestion window (RFC 5681
    /// §3.1: cwnd bounds SND.NXT minus SND.UNA).
    fn drain_writes(&mut self, out: &mut VecDeque<BytesMut>) {
        // The registered-flow exit: frames build here (same sequence
        // cursor, same window arithmetic) but leave through the TUN's
        // write channel, skipping the outbox and the writer thread.
        // The connection stays the single source of truth for the
        // sequence space, which is the bug the relay-side fast path
        // taught (its local cursor started at the wrong base).
        // The downlink fast drain is parked: the uplink's ACKs and
        // the downlink's data both land in the TUN write channel, and
        // the competition dropped the uplink from 271 to 37 Mbit/s
        // (measured, three rounds). The uplink fast path (the proven
        // win: +36% and zero retransmissions) writes its payload to
        // the outbound socket, but its ACKs still ride this channel;
        // arbitrating the two is a design piece, not a flag.
        // The downlink fast drain stays parked: re-enabled with the
        // 1024-deep channel, it still degrades both directions (466
        // up to 364, 2432 down to 1990, measured). The TUN write
        // channel is a shared resource; the uplink's direct ACK and
        // the downlink's frames interleaving through it costs more
        // than the outbox-and-writer hop it saves. A separate write
        // lane (or io-thread arbitration) is the design piece.
        let inflight = self
            .connection
            .send_nxt()
            .wrapping_sub(self.connection.send_una());
        // The sender's two bounds (RFC 9293 §3.1): the congestion
        // window and the window the receiver advertised. Without the
        // second, a grown congestion window overshoots the receiver's
        // buffer; the dropped excess leaves holes nothing will fill
        // while retransmission is not wired.
        let sendable = self.cc.window().min(self.connection.peer_window());
        let mut budget = sendable.saturating_sub(inflight) as usize;
        let mut lane = self.write_lane.lock().expect("write lane");
        while let Some(write) = lane.writes.front_mut() {
            if write.is_empty() {
                // The host's shutdown marker: a FIN after any data. The
                // FIN is one byte past the stream and leaves ungated;
                // a window with no room must not wedge the close.
                let marker = lane.writes.pop_front().expect("front held the marker");
                let _ = marker;
                drop(lane);
                let reaction = self.connection.fin_reaction();
                if reaction.flags != 0 {
                    let frame = emit_tcp(self.server, self.client, &reaction, &[], &[]);
                    out.push_back(BytesMut::from(&frame[..]));
                    self.fin_at = Some(reaction.seq);
                    self.data_sent_at = Some(Instant::now());
                    self.data_retries = 0;
                    self.connection.mark_fin_sent();
                    self.connection
                        .send_advance(u32::from(reaction.flags & 0x03 != 0));
                }
                return;
            }
            if budget == 0 {
                break;
            }
            let take = write.len().min(budget).min(self.connection.mss() as usize);
            let more_after = write.len() > take;
            let reaction = Reaction {
                seq: self.connection.send_nxt(),
                ack: self.connection.recv_nxt(),
                flags: if more_after { 0x10 } else { 0x18 },
                window: self.connection.advertised_window(),
                delivered: Vec::new(),
                held: false,
                gap_filled: false,
            };
            let frame = emit_tcp(self.server, self.client, &reaction, &[], &write[..take]);
            out.push_back(BytesMut::from(&frame[..]));
            if self.flight.is_empty() {
                self.flight_base = self.connection.send_nxt();
                self.data_sent_at = Some(Instant::now());
                self.data_retries = 0;
            }
            self.flight.extend_from_slice(&write[..take]);
            self.connection.send_advance(take as u32);
            let drained_dry = {
                write.drain(..take);
                write.is_empty()
            };
            budget -= take;
            lane.bytes -= take;
            if drained_dry {
                lane.writes.pop_front();
            }
        }
        // The stalled-drain alarm: output this drain left behind. A
        // rate-limited line per flow per second, paid inside the lock
        // the drain already holds — a real stall names its bounds; a
        // healthy trickle moves between lines and never prints.
        if lane.bytes > 0
            && lane.bytes == self.diag_queued
            && self
                .diag_at
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
        {
            self.diag_at = Some(Instant::now());
            self.diag_queued = lane.bytes;
            eprintln!(
                "vfawn: stalled drain flow={:?} state={:?} queued={} mss={} cc={} peer_win={} inflight={} flight={} retries={} persist={} fin_at={}",
                self.flow_key,
                self.connection.state(),
                lane.bytes,
                self.connection.mss(),
                self.cc.window(),
                self.connection.peer_window(),
                self.connection
                    .send_nxt()
                    .wrapping_sub(self.connection.send_una()),
                self.flight.len(),
                self.data_retries,
                self.persist_at.is_some(),
                self.fin_at.is_some(),
            );
        } else if lane.bytes == 0 {
            self.diag_queued = 0;
        }
        // Output waiting with nothing in flight and no sendable budget:
        // arm the persist clock. Whichever bound closed — the peer's
        // window (which it may believe open, owing us no packet that
        // says so) or the congestion window (collapsed by loss) — the
        // probe is the only thing that ever reopens it from our side
        // (RFC 9293 §3.8.2, generalized past the literal zero window:
        // a small positive window with no room is the same silence).
        let inflight = self
            .connection
            .send_nxt()
            .wrapping_sub(self.connection.send_una());
        if lane.bytes > 0
            && self.flight.is_empty()
            && inflight == 0
            && self.cc.window().min(self.connection.peer_window()) == 0
            && self.persist_at.is_none()
            && self.persist_retries < PERSIST_RETRY_MAX
        {
            self.persist_at = Some(Instant::now());
            self.persist_retries = 0;
        }
    }
}

impl TcpSlot {
    /// One reaction onto the wire; the handshake's SYN-ACK is the only
    /// segment that carries options.
    fn emit(&mut self, reaction: &Reaction, out: &mut VecDeque<BytesMut>) {
        let options = if reaction.flags & 0x02 != 0 {
            self.connection.handshake_options(Instant::now())
        } else {
            Vec::new()
        };
        let frame = emit_tcp(self.server, self.client, reaction, &options, &[]);
        out.push_back(BytesMut::from(&frame[..]));
        self.connection
            .send_advance(u32::from(reaction.flags & 0x03 != 0));
    }
}

impl TcpSlot {
    /// Pronounce the flow dead and TELL the peer. A flow that goes
    /// silent leaves the far end's read waiting forever, which is
    /// a hang wearing a timeout's clothes; the reset carries the last
    /// cursor we hold (RFC 9293 §3.4.3's "send a reset" for an
    /// aborted connection), the host learns the flow is gone, and the
    /// slot goes inert instead of paying retries forever.
    fn give_up(&mut self, out: &mut VecDeque<BytesMut>) {
        let reset = Reaction::segment(
            self.connection.send_nxt(),
            self.connection.recv_nxt(),
            ctl::RST | ctl::ACK,
            0,
        );
        let frame = emit_tcp(self.server, self.client, &reset, &[], &[]);
        out.push_back(BytesMut::from(&frame[..]));
        self.connection.abandon();
        self.flight.clear();
        self.data_sent_at = None;
        self.fin_at = None;
        self.persist_at = None;
        if let Some(to_host) = &self.to_host {
            let _ = to_host.send(HostEvent::Closed);
        }
    }

    /// Hand the fast path's accumulated bytes to the session channel.
    /// They left the fast path already acknowledged — the refusal of a
    /// non-blocking write must not turn them into acknowledged-but-
    /// undelivered bytes — and the relay's async write is the one
    /// place that can wait out the socket's pressure. Without a
    /// session (the flow folded after teardown), nobody downstream
    /// wants them and the accumulator just empties.
    #[cfg(target_os = "linux")]
    fn fold_back_to_session(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(to_host) = &self.to_host {
            let _ = to_host.send(HostEvent::Bytes(bytes.to_vec()));
        }
    }
}

impl SlotLogic for TcpSlot {
    fn on_packet(
        &mut self,
        packet: &[u8],
        out: &mut VecDeque<BytesMut>,
        _pool: &BufferPool,
        _mtu: usize,
    ) {
        // The family decides where the segment starts; the machine
        // downstream is family-blind (sequence space and flags).
        let payload = match packet.first().map(|byte| byte >> 4) {
            Some(4) => {
                let Ok((ip, payload)) = Ipv4Header::parse(packet) else {
                    return;
                };
                if ip.protocol != IpProtocol::Tcp {
                    return;
                }
                payload
            }
            Some(6) => {
                let Ok((ip, rest)) = vfawn_wire::ipv6::Ipv6Header::parse(packet) else {
                    return;
                };
                let Ok(transport) = vfawn_wire::ipv6::V6Payload::walk(ip.next_header, rest) else {
                    return;
                };
                if transport.protocol != IpProtocol::Tcp {
                    return;
                }
                transport.bytes
            }
            _ => return,
        };
        let Ok((header, _segment_payload)) = TcpHeader::parse(payload) else {
            return;
        };
        if !self.judged {
            self.judge(packet, out);
        }
        if self.refused {
            return;
        }
        // Any inbound segment answers the keepalive question — the
        // probe clock disarms and the budget resets (RFC 9293
        // §3.8.1: an incoming segment restarts the keep-alive timer).
        self.keepalive_at = None;
        self.keepalive_probes = 0;

        let inbound = Inbound::parse(&header, payload);

        // The lane entry, when the relay registered this flow. Its
        // shared receive cursor runs ahead of the machine while the
        // device's read dispatch claims steady segments: catch the
        // machine up before any acceptance test reads its cursor, or
        // the first slow-path segment after a fast burst (a window
        // update, a teardown) looks out of order against stale state.
        // The lane is the Linux fast path's registry; where it does
        // not exist, the slow path below is the whole story.
        #[cfg(target_os = "linux")]
        let entry = {
            let lane = crate::splice_lane::SpliceLane::global();
            let entry = lane.entry_for(&self.flow_key);
            // The catch-up does not wait for the entry's activation:
            // an inactive entry (deactivated under outbound pressure)
            // with a machine behind the shared cursor is exactly the
            // window where a retransmission of already-claimed bytes
            // re-delivered — the dispatch had written them and
            // acknowledged them, the machine never learned, the slot's
            // fast path wrote them again, and the server read a
            // duplicated stream. Adopting the wire's position whenever
            // the flow rides the lane closes the hole for every entry
            // state.
            if let Some(entry) = &entry {
                self.connection.catchup_recv(entry.recv_nxt_value());
            }
            entry
        };

        // The payload fast path: a registered relay flow's steady data
        // segment skips the session channel and the relay task
        // entirely. The state machine's role shrinks to the two
        // sequence-cursor lines inside fast_accept; the ACK leaves
        // exactly as the slow path's would. What still arrives here
        // is the bootstrap segment (before the entry activates for
        // the read dispatch) or a dispatch fallback — outbound
        // backpressure or a contested TUN channel.
        #[cfg(target_os = "linux")]
        if let Some(entry) = &entry
            && self.connection.fast_acceptable(&inbound)
        {
            // Backpressure honesty: the outbound fd is non-blocking,
            // and a socket the peer is not draining refuses writes.
            // Every byte already acknowledged must still reach the
            // relay, so a refused flush hands the accumulator to the
            // session channel (whose write waits out the pressure)
            // and the flow leaves the fast path — this segment then
            // rides the slow path below, unacknowledged until it is
            // actually deliverable.
            {
                if !entry.is_active() {
                    // Adoption before activation: a deactivation (an
                    // outbound write refused under pressure) left the
                    // shared cursor ahead of the machine — the bytes
                    // the dispatch claimed, staged, and acknowledged.
                    // Re-arming the entry from the machine's stale
                    // position rewound the wire's truth, and every
                    // in-flight successor then mismatched ahead into
                    // the slow path: a quarter of all segments, and
                    // the throughput's sawtooth. The machine takes the
                    // wire's position first; the entry arms at the
                    // truth.
                    self.connection.catchup_recv(entry.recv_nxt_value());
                    entry.activate(
                        self.connection.recv_nxt(),
                        self.connection.send_nxt(),
                        self.connection.fast_window(),
                    );
                }
                // Write through, never accumulate: this branch sees the
                // bootstrap and the fallback, and the read dispatch
                // writes the same socket from the I/O loop. An
                // accumulator here held a four-byte length prefix while
                // the dispatch wrote the segment after it — the server
                // read the prefix's duplicate inside the next burst and
                // tore the connection down. One segment, one write,
                // order follows arrival.
                if crate::splice_lane::send_payload(entry.outbound_fd(), inbound.payload).is_err() {
                    self.fold_back_to_session(inbound.payload);
                    entry.deactivate();
                }
                let seq_before = self.connection.recv_nxt();
                let ack = self.connection.fast_accept(&inbound);
                // Keep the shared cursor in step for the read dispatch:
                // the compare fails only if the dispatch itself already
                // moved past, which the machine's next catch-up absorbs.
                entry.advance_recv(seq_before, self.connection.recv_nxt());
                entry.refresh(self.connection.send_nxt(), self.connection.fast_window());
                // This branch is the bootstrap and the fallback now (the
                // read dispatch claims the steady segments), so its ACK
                // rides the ordinary outbox-and-writer exit — the write
                // channel keeps its single producer, which the
                // multi-pusher experiment measured into both a downlink
                // collapse and end-of-test stalls.
                self.emit(&ack, out);
                return;
            }
        }

        let una_before = self.connection.send_una();
        let reaction = self.connection.on_segment(&inbound);

        // Congestion reporting rides every inbound acknowledgment: the
        // reaction can be silent when an ACK only moved SND.UNA, but
        // those are exactly the acknowledgments the window grows on
        // (RFC 5681 §3.1 counts acknowledgments, not replies). The
        // half-window guard keeps an old or replayed ACK from looking
        // like a full wrap of sequence space.
        if inbound.flags & 0x10 != 0 {
            let delta = inbound.ack.wrapping_sub(una_before);
            if delta > 0 && delta < u32::MAX / 2 {
                // The RTT sample rides the timestamp echo: an ACK's
                // TSecr names the TSval of the segment it
                // acknowledges, and our clock holds that send time
                // (RFC 7323 §3.1). No echo, no sample — the None the
                // trait documents.
                let rtt = inbound
                    .options
                    .timestamps
                    .and_then(|received| self.connection.rtt_sample(received.tsecr));
                self.cc.on_signal(
                    self.connection.mss(),
                    Signal::Acked {
                        newly: delta.min(u32::from(u16::MAX)),
                        rtt,
                    },
                );
            }
        }

        // Prune the flight by what the connection accepted
        // (SND.UNA), never by the raw ACK field: an acknowledgment
        // beyond what was sent moves nothing (RFC 9293 §3.3.6).
        let una = self.connection.send_una();
        if !self.flight.is_empty() {
            let end = self.flight_base.wrapping_add(self.flight.len() as u32);
            let fully_acked = una == end || una.wrapping_sub(end) < u32::MAX / 2;
            if fully_acked {
                self.flight.clear();
                self.data_sent_at = None;
                self.data_retries = 0;
            } else if una.wrapping_sub(self.flight_base) < u32::MAX / 2 {
                let drop_bytes =
                    (una.wrapping_sub(self.flight_base) as usize).min(self.flight.len());
                self.flight.drain(..drop_bytes);
                self.flight_base = una;
                // An acknowledgment that advanced proves the path is
                // carrying: the remaining flight gets a fresh timeout
                // and the backoff forgets its fears (RFC 6298 §5.3,
                // without which a long transfer collapses its window
                // on a timer that never stopped running).
                self.data_sent_at = Some(Instant::now());
                self.data_retries = 0;
            }
        }
        if self.connection.state() == TcpState::Established {
            self.synack_at = None;
        }
        if self.connection.state() == TcpState::Closed {
            self.fin_at = None;
        }

        // Establish before delivering: the completing ACK may carry
        // data, and those bytes need the channel the handshake just
        // earned.
        self.announce();
        if !reaction.delivered.is_empty() {
            let mut session_gone = false;
            if let Some(to_host) = &self.to_host {
                // A refused send means the session side is gone — the
                // relay's dial failed or its task died. Acknowledging
                // further bytes into a dead service is the silent
                // forever-wait this flow must not become: it resets
                // now, with the peer told (RFC 9293 §3.4.3).
                session_gone = to_host
                    .send(HostEvent::Bytes(reaction.delivered.clone()))
                    .is_err();
            }
            if session_gone {
                self.give_up(out);
                return;
            }
        }

        if reaction.flags & 0x02 != 0 {
            // The handshake's answer is now outstanding: its retry
            // clock starts here (RFC 9293 §3.4).
            self.synack_at = Some(Instant::now());
            self.synack_retries = 0;
        }
        // Every acknowledgment leaves with its segment: pooling them
        // (tried, measured) starves the peer's ACK-clocked send window
        // threefold on upload, which no saved frame ever repaid.
        if reaction.flags != 0 {
            self.emit(&reaction, out);
        }

        // Half-close (RFC 9293 §3.5): the peer's FIN ends its
        // direction; the host's read side sees EOF while its write
        // lane stays open, so the write drain continues in
        // CLOSE-WAIT. Full closure keeps the same event.
        match self.connection.state() {
            TcpState::CloseWait | TcpState::Closed => {
                if let Some(to_host) = &self.to_host {
                    let _ = to_host.send(HostEvent::Closed);
                }
            }
            _ => {
                self.drain_writes(out);
            }
        }

        // The read dispatch stamps its ACKs from the entry's view of
        // the send cursor; the slow path just moved that cursor (data,
        // FIN, window arithmetic), so the view re-syncs here. A stale
        // view costs only hit rate — the dispatch declines, the next
        // segment rides this same path — never correctness.
        #[cfg(target_os = "linux")]
        if let Some(entry) = &entry
            && entry.is_active()
        {
            entry.refresh(self.connection.send_nxt(), self.connection.fast_window());
        }

        // News about the peer's window retires the persist clock: the
        // drain that stalled behind the closed window runs on the next
        // idle sweep, a millisecond away.
        if self.persist_at.is_some() && self.connection.peer_window() > 0 {
            self.persist_at = None;
            self.persist_retries = 0;
        }
    }

    fn timer_wanted(&self) -> Option<Duration> {
        match self.connection.state() {
            TcpState::SynReceived if self.synack_retries < SYNACK_RETRY_MAX => {
                self.synack_at.map(|at| {
                    (at + rto_backoff(self.synack_retries))
                        .saturating_duration_since(Instant::now())
                })
            }
            TcpState::Established | TcpState::CloseWait
                if !self.flight.is_empty() && self.data_retries < DATA_RETRY_MAX =>
            {
                self.data_sent_at.map(|at| {
                    (at + rto_backoff(self.data_retries)).saturating_duration_since(Instant::now())
                })
            }
            TcpState::LastAck if self.data_retries < DATA_RETRY_MAX => {
                self.data_sent_at.map(|at| {
                    (at + rto_backoff(self.data_retries)).saturating_duration_since(Instant::now())
                })
            }
            // The keepalive clock: when everything else is quiet and
            // the probe is armed, it is the next thing the slot owes
            // the wire (RFC 9293 §3.8.1). The stored deadline is the
            // next action — first probe after the idle window, each
            // successor after the interval.
            TcpState::Established
                if self.keepalive_at.is_some() && self.keepalive_probes < KEEPALIVE_PROBE_MAX =>
            {
                self.keepalive_at
                    .map(|at| at.saturating_duration_since(Instant::now()))
            }
            // The persist clock runs beside the retransmit one: a
            // closed window with output waiting owes the wire a
            // probe, whether or not anything is in flight.
            TcpState::Established | TcpState::CloseWait
                if self.persist_at.is_some() && self.persist_retries < PERSIST_RETRY_MAX =>
            {
                self.persist_at.map(|at| {
                    (at + rto_backoff(self.persist_retries))
                        .saturating_duration_since(Instant::now())
                })
            }
            _ => None,
        }
    }

    fn on_timer(&mut self, out: &mut VecDeque<BytesMut>, _pool: &BufferPool) {
        match self.connection.state() {
            TcpState::SynReceived => {
                // The handshake's answer again (RFC 9293 §3.4): the
                // same sequence, a longer wait if it fires again.
                if let Some(reaction) = self.connection.synack_retransmit() {
                    let options = self.connection.handshake_options(Instant::now());
                    let frame = emit_tcp(self.server, self.client, &reaction, &options, &[]);
                    out.push_back(BytesMut::from(&frame[..]));
                    self.synack_retries = self.synack_retries.saturating_add(1);
                    self.synack_at = Some(Instant::now());
                }
            }
            TcpState::Established | TcpState::CloseWait | TcpState::LastAck => {
                if self.data_retries >= DATA_RETRY_MAX {
                    // Dead, pronounced: the wire has had every chance,
                    // the host learns the flow is gone, and the slot
                    // goes inert instead of paying retries forever.
                    self.give_up(out);
                    return;
                }
                // The persist probe: a closed window with output
                // waiting is a deadlock the peer cannot break — it
                // believes its side healthy and owes us no packet —
                // so one byte of the waiting output goes out to ask
                // (RFC 9293 §3.8.2). The answer's window field is the
                // news; the normal drain takes it from there.
                // The keepalive probe: a bare ACK asking the peer
                // "are you there?" (RFC 9293 §3.8.1 — the probe
                // carries no data, just the current cursors). Each
                // unanswered probe arms the next; the budget
                // exhausted pronounces the flow dead with the peer
                // told (the shared give-up sends the reset).
                if let Some(at) = self.keepalive_at
                    && Instant::now() >= at
                {
                    if self.keepalive_probes >= KEEPALIVE_PROBE_MAX {
                        self.give_up(out);
                        return;
                    }
                    let probe = Reaction::segment(
                        self.connection.send_nxt(),
                        self.connection.recv_nxt(),
                        ctl::ACK,
                        self.connection.advertised_window(),
                    );
                    let frame = emit_tcp(self.server, self.client, &probe, &[], &[]);
                    out.push_back(BytesMut::from(&frame[..]));
                    self.keepalive_probes += 1;
                    self.keepalive_at = Some(Instant::now() + KEEPALIVE_INTERVAL);
                }
                if self.persist_at.is_some() {
                    if self.connection.peer_window() > 0 {
                        self.persist_at = None;
                        self.persist_retries = 0;
                    } else {
                        self.persist_retries = self.persist_retries.saturating_add(1);
                        self.persist_at = Some(Instant::now());
                        if self.persist_retries >= PERSIST_RETRY_MAX {
                            // Written off: the peer will not read us
                            // again; the shared give-up resets it.
                            self.give_up(out);
                            return;
                        }
                        let mut lane = self.write_lane.lock().expect("write lane");
                        let front_nonempty =
                            lane.writes.front().is_some_and(|write| !write.is_empty());
                        if front_nonempty {
                            let probe;
                            {
                                let front = lane.writes.front_mut().expect("front held data");
                                probe = front[0];
                                front.drain(..1);
                                if front.is_empty() {
                                    lane.writes.pop_front();
                                }
                            }
                            lane.bytes -= 1;
                            drop(lane);
                            let reaction = Reaction {
                                seq: self.connection.send_nxt(),
                                ack: self.connection.recv_nxt(),
                                flags: 0x18,
                                window: self.connection.advertised_window(),
                                delivered: Vec::new(),
                                held: false,
                                gap_filled: false,
                            };
                            let frame =
                                emit_tcp(self.server, self.client, &reaction, &[], &[probe]);
                            out.push_back(BytesMut::from(&frame[..]));
                            if self.flight.is_empty() {
                                self.flight_base = self.connection.send_nxt();
                            }
                            self.flight.push(probe);
                            self.connection.send_advance(1);
                            self.data_sent_at = Some(Instant::now());
                            self.data_retries = 0;
                        }
                        return;
                    }
                }
                if self.flight.is_empty() {
                    // With no data owed, the only outstanding thing can
                    // be our FIN: the passive closer's patience pays
                    // for one more farewell (RFC 9293 §3.5).
                    if self.connection.state() == TcpState::LastAck
                        && let Some(seq) = self.fin_at
                    {
                        let reaction = Reaction {
                            seq,
                            ack: self.connection.recv_nxt(),
                            flags: 0x11,
                            window: self.connection.advertised_window(),
                            delivered: Vec::new(),
                            held: false,
                            gap_filled: false,
                        };
                        let frame = emit_tcp(self.server, self.client, &reaction, &[], &[]);
                        out.push_back(BytesMut::from(&frame[..]));
                        self.data_retries = self.data_retries.saturating_add(1);
                        self.data_sent_at = Some(Instant::now());
                    }
                    return;
                }
                // Loss, pronounced: the window collapses (RFC 5681
                // §3.1 via RFC 6298 §5) and the earliest outstanding
                // bytes leave again in segment-sized pieces.
                self.cc.on_signal(self.connection.mss(), Signal::Timeout);
                let mss = self.connection.mss() as usize;
                let budget = self
                    .cc
                    .window()
                    .min(self.connection.peer_window())
                    .saturating_sub(1) as usize;
                let mut offset = 0usize;
                while offset < self.flight.len() && offset < budget {
                    let take = (self.flight.len() - offset).min(mss).min(budget - offset);
                    let more_after = offset + take < self.flight.len();
                    let reaction = Reaction {
                        seq: self.flight_base.wrapping_add(offset as u32),
                        ack: self.connection.recv_nxt(),
                        flags: if more_after { 0x10 } else { 0x18 },
                        window: self.connection.advertised_window(),
                        delivered: Vec::new(),
                        held: false,
                        gap_filled: false,
                    };
                    let frame = emit_tcp(
                        self.server,
                        self.client,
                        &reaction,
                        &[],
                        &self.flight[offset..offset + take],
                    );
                    out.push_back(BytesMut::from(&frame[..]));
                    offset += take;
                }
                self.data_retries = self.data_retries.saturating_add(1);
                self.data_sent_at = Some(Instant::now());
            }
            _ => {}
        }
    }

    fn on_idle(&mut self, out: &mut VecDeque<BytesMut>) {
        // The keepalive question: a flow with no activity for the
        // idle window arms its probe clock (the next timer fire
        // sends the first probe). A flow that just had activity
        // disarmed it in on_packet.
        if matches!(self.connection.state(), TcpState::Established)
            && self.keepalive_at.is_none()
            && self.connection.send_una() == self.connection.send_nxt()
            && self.flight.is_empty()
            && self.write_lane.lock().expect("write lane").bytes == 0
        {
            // The arm happens only after the full idle window of
            // quiet — use the last inbound activity, which on_packet
            // tracks by disarming; here we re-arm with the delay.
            self.keepalive_at = Some(Instant::now() + KEEPALIVE_IDLE);
            self.keepalive_probes = 0;
        }
        // Host writes that arrived after the last packet: their only
        // ride is this idle sweep; CLOSE-WAIT writes still leave
        // (half-close: the answer direction stays ours).
        if matches!(
            self.connection.state(),
            TcpState::Established | TcpState::CloseWait
        ) {
            self.drain_writes(out);
        }
    }
}

/// The session-facing transport: host reads pull from slot events,
/// host writes push into the slot's lane.
struct NativeTcpIo {
    events: tokio::sync::mpsc::UnboundedReceiver<HostEvent>,
    write_lane: Arc<std::sync::Mutex<WriteLane>>,
    /// The shard's wake flag: a host write sets it so the loop wakes
    /// from its idle sleep and the drain runs now, not at the next
    /// sweep. Without it, a small interactive write (four bytes of a
    /// protocol length prefix) sat in the lane for the sleep cadence —
    /// forty milliseconds of silence that the far end's protocol timer
    /// read as death.
    shard_wake: Arc<ShardBell>,
    pending: VecDeque<u8>,
    closed: bool,
}

#[async_trait::async_trait]
impl TcpTransport for NativeTcpIo {
    async fn read_owned(&mut self) -> io::Result<Vec<u8>> {
        // The parked wait owns nothing: the channel carries the bytes,
        // and the Vec below lives only until the caller finishes with
        // it — an idle session between reads holds no buffer at all.
        // The first chunk arrives as its own Vec and carries whatever
        // else is queued onto it, so one return still holds a relay's
        // worth of segments rather than waking the writer per segment.
        const CHUNK_TARGET: usize = 2048;
        loop {
            if !self.pending.is_empty() {
                let mut chunk = std::mem::take(&mut self.pending);
                while chunk.len() < CHUNK_TARGET {
                    match self.events.try_recv() {
                        Ok(HostEvent::Bytes(more)) => chunk.extend(more),
                        Ok(HostEvent::Established) => {}
                        Ok(HostEvent::Closed) => {
                            self.closed = true;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                return Ok(chunk.into());
            }
            if self.closed {
                return Ok(Vec::new());
            }
            match self.events.recv().await {
                Some(HostEvent::Bytes(bytes)) => {
                    let mut chunk = bytes;
                    while chunk.len() < CHUNK_TARGET {
                        match self.events.try_recv() {
                            Ok(HostEvent::Bytes(more)) => chunk.extend(more),
                            Ok(HostEvent::Established) => {}
                            Ok(HostEvent::Closed) => {
                                self.closed = true;
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    return Ok(chunk);
                }
                Some(HostEvent::Established) => continue,
                Some(HostEvent::Closed) => self.closed = true,
                None => self.closed = true,
            }
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.pending.is_empty() {
                let take = self.pending.len().min(buf.len());
                for (slot, byte) in self.pending.drain(..take).enumerate() {
                    buf[slot] = byte;
                }
                return Ok(take);
            }
            if self.closed {
                return Ok(0);
            }
            match self.events.recv().await {
                Some(HostEvent::Bytes(bytes)) => {
                    self.pending.extend(bytes);
                    // Carry whatever else already queued: one return
                    // holds as many segments as fit the caller's
                    // buffer, so a relay writes one large chunk instead
                    // of waking and writing per segment. A close that
                    // lands mid-drain is remembered, not swallowed:
                    // the bytes already held leave first, the next read
                    // reports the end.
                    while self.pending.len() < buf.len() {
                        match self.events.try_recv() {
                            Ok(HostEvent::Bytes(more)) => self.pending.extend(more),
                            Ok(HostEvent::Established) => {}
                            Ok(HostEvent::Closed) => {
                                self.closed = true;
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                }
                Some(HostEvent::Established) => continue,
                Some(HostEvent::Closed) => self.closed = true,
                None => self.closed = true,
            }
        }
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // Backpressure the host against the wire: a full lane waits
        // instead of growing, so the kernel socket buffers upstream
        // slow the source the way the network would.
        while self.write_lane.lock().expect("write lane").bytes >= LANE_CAP {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let mut lane = self.write_lane.lock().expect("write lane");
        lane.bytes += data.len();
        lane.writes.push_back(data.to_vec());
        drop(lane);
        self.shard_wake.knock();
        Ok(data.len())
    }

    async fn shutdown_write(&mut self) -> io::Result<()> {
        // The empty marker is not data and never waits behind the cap.
        self.write_lane
            .lock()
            .expect("write lane")
            .writes
            .push_back(Vec::new());
        Ok(())
    }

    async fn abort(&mut self) -> io::Result<()> {
        let mut lane = self.write_lane.lock().expect("write lane");
        lane.writes.clear();
        lane.bytes = 0;
        Ok(())
    }
}

/// The backend the facade selects.
#[derive(Clone)]
pub struct NativeBackend {
    pub shards: usize,
    /// Which congestion controller each new connection runs. The type
    /// is the one `StackConfig.congestion` carries, so a facade hands
    /// its configured choice straight through.
    pub congestion: vfawn_core::CongestionAlgo,
    /// SYN cookies on: every SYN is answered statelessly and the ISN
    /// carries the proof (RFC 4987 §3.3, the countermeasure the
    /// reference stacks ship without).
    pub syn_cookies: bool,
    /// The half-open bound when cookies are off.
    pub backlog: usize,
    /// The segment size the connection answers with. The device's MTU
    /// minus its headers is the honest value; the RFC default is the
    /// fallback until SYN options are parsed (RFC 9293 §3.7.1).
    pub mss: u16,
}

impl Default for NativeBackend {
    fn default() -> Self {
        Self {
            shards: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .min(4),
            congestion: vfawn_core::CongestionAlgo::default(),
            syn_cookies: true,
            backlog: 128,
            mss: DEFAULT_MSS,
        }
    }
}

impl NativeBackend {
    /// One controller source per spawn: each slot builds its own from
    /// this and owns it, so nothing shared sits between a connection
    /// and its window. BBR is a v0.5 module; until it exists the
    /// choice falls back to CUBIC rather than failing a valid
    /// configuration.
    fn cc_factory(
        choice: vfawn_core::CongestionAlgo,
        mss: u16,
    ) -> Arc<dyn Fn() -> Box<dyn CongestionAlgo> + Send + Sync> {
        match choice {
            vfawn_core::CongestionAlgo::Reno => Arc::new(move || Box::new(Reno::new(mss))),
            vfawn_core::CongestionAlgo::Bbr => {
                Arc::new(move || Box::new(crate::congestion::Bbr::new(mss)))
            }
            _ => Arc::new(move || Box::new(Cubic::new(mss))),
        }
    }
}

/// Everything the spawn path threads through the factory closure.
struct SpawnShared {
    handler: Arc<dyn SessionHandler>,
    sessions: mpsc::SyncSender<SessionHandoff>,
    udp_sessions: mpsc::SyncSender<crate::udp_slot::UdpHandoff>,
    accept: Arc<std::sync::Mutex<AcceptQueue>>,
    cc_factory: Arc<dyn Fn() -> Box<dyn CongestionAlgo> + Send + Sync>,
    mss: u16,
    /// Each shard's doorbell, filled once the shards exist: a slot's
    /// lane rings its own shard's bell on host writes, so an
    /// interactive write drains immediately.
    shard_wakes: Arc<std::sync::OnceLock<Vec<Arc<ShardBell>>>>,
}

/// A ready session handed to the runtime side.
struct SessionHandoff {
    flow: FlowInfo,
    events: tokio::sync::mpsc::UnboundedReceiver<HostEvent>,
    write_lane: Arc<std::sync::Mutex<WriteLane>>,
    shard_wake: Arc<ShardBell>,
    tracker: Option<Arc<dyn vfawn_core::FlowTrackerHook>>,
}

impl StackBackend for NativeBackend {
    fn spawn(
        self: Box<Self>,
        device: Box<dyn PacketDevice>,
        handler: Arc<dyn SessionHandler>,
    ) -> io::Result<StackHandle> {
        let handle = StackHandle::new();
        let write_device = device.duplicate()?;

        // The read dispatch: a registered flow's steady segments are
        // claimed inside the device's own I/O loop — the channel,
        // producer, ring, and shard crossings the slow path pays per
        // segment become none, and the answers leave through the
        // device's own write path at the end of the read batch.
        #[cfg(target_os = "linux")]
        {
            let lane = crate::splice_lane::SpliceLane::global();
            device.set_read_dispatch(vfawn_core::device::ReadDispatch {
                claim: Arc::new(|packet: &[u8], produced: &mut Vec<BytesMut>| {
                    lane.try_dispatch(packet, produced)
                }),
                finish: Arc::new(|| lane.flush_staged()),
            });
        }

        let (sessions_tx, sessions_rx) = mpsc::sync_channel::<SessionHandoff>(1024);
        let (udp_tx, udp_rx) = mpsc::sync_channel::<crate::udp_slot::UdpHandoff>(1024);
        let shard_wakes: Arc<std::sync::OnceLock<Vec<Arc<ShardBell>>>> =
            Arc::new(std::sync::OnceLock::new());

        let shared = Arc::new(SpawnShared {
            handler: Arc::clone(&handler),
            sessions: sessions_tx,
            udp_sessions: udp_tx,
            accept: Arc::new(std::sync::Mutex::new(AcceptQueue::new(
                self.syn_cookies,
                self.backlog,
                Box::new(FixedSecret(flood_secret())),
            ))),
            cc_factory: Self::cc_factory(self.congestion, self.mss),
            mss: self.mss,
            shard_wakes: Arc::clone(&shard_wakes),
        });

        let factory_shared = Arc::clone(&shared);
        let icmp_table = Arc::new(crate::icmp::IcmpTable::new());
        // The error lane's reader rides with the session surfaces
        // (the close-on-IcmpError wiring); the sender end is live the
        // moment the first datagram slot exists.
        let (error_tx, _error_lane) = mpsc::sync_channel::<FlowInfo>(1024);
        let icmp_handler = Arc::clone(&shared.handler);
        let icmp_table_for_slots = Arc::clone(&icmp_table);
        let logic_factory: LogicFactory = Arc::new(move |flow: &FlowKey| {
            // Every flow's slot knows its shard's doorbell — the host's
            // writes ring it through the slot's lane — resolved here so
            // the datagram slots and the connection slots share one
            // lookup shape. Before the shards exist (nothing has flowed
            // yet) a private bell stands in; it rings nothing.
            let shard_bell = factory_shared
                .shard_wakes
                .get()
                .and_then(|bells| {
                    bells
                        .get(crate::shards::shard_hash_of(flow, bells.len()))
                        .cloned()
                })
                .unwrap_or_else(|| Arc::new(ShardBell::new()));
            // ICMP flows ride the datagram slot: echo answered in
            // place, errors correlated, no connection to hold — both
            // families, the kinds tell them apart.
            if flow.protocol == IpProtocol::Icmp || flow.protocol == IpProtocol::Icmpv6 {
                return Box::new(crate::icmp_slot::IcmpSlot::new(
                    Arc::clone(&icmp_handler),
                    Arc::clone(&icmp_table_for_slots),
                    error_tx.clone(),
                )) as Box<dyn SlotLogic>;
            }
            // Datagram flows ride their own slot: no handshake, no
            // sequence space — the first datagram earns the session
            // and the idle clock owns the rest.
            if flow.protocol == IpProtocol::Udp {
                return Box::new(crate::udp_slot::UdpSlot::new(
                    Arc::clone(&factory_shared.handler),
                    factory_shared.udp_sessions.clone(),
                    shard_bell,
                )) as Box<dyn SlotLogic>;
            }
            // Only v4 flows ride the native stack; anything else gets a
            // sink slot so the shard keeps flowing.
            let Some((client, server)) = v4_ends(flow) else {
                return Box::new(SinkSlot) as Box<dyn SlotLogic>;
            };
            // The accept layer's say on the new flow: cookie mode
            // hands every SYN a secret-keyed ISN at no cost, backlog
            // mode drops the SYN outright once the queue is full.
            let source = std::net::SocketAddr::new(flow.src, flow.src_port);
            let Some(isn) = factory_shared
                .accept
                .lock()
                .expect("accept lock")
                .admit(source, Instant::now())
            else {
                return Box::new(SinkSlot) as Box<dyn SlotLogic>;
            };
            let write_lane = Arc::new(std::sync::Mutex::new(WriteLane::new()));

            Box::new(TcpSlot {
                connection: ServerConnection::new(isn, factory_shared.mss),
                flow_key: *flow,
                client,
                server,
                handler: Arc::clone(&factory_shared.handler),
                accept: Arc::clone(&factory_shared.accept),
                sessions: factory_shared.sessions.clone(),
                flow: FlowInfo {
                    network: Network::Tcp,
                    source,
                    destination: std::net::SocketAddr::new(flow.dst, flow.dst_port),
                },
                write_lane,
                shard_wake: shard_bell,
                cc: (factory_shared.cc_factory)(),
                to_host: None,
                judged: false,
                refused: false,
                flight: Vec::new(),
                flight_base: 0,
                data_sent_at: None,
                data_retries: 0,
                synack_at: None,
                synack_retries: 0,
                fin_at: None,
                persist_at: None,
                persist_retries: 0,
                diag_at: None,
                diag_queued: 0,
                keepalive_at: None,
                keepalive_probes: 0,
                tracker: None,
            })
        });

        let shard_count = self.shards;
        let shards = Shards::start(
            device,
            write_device,
            ShardConfig {
                shards: shard_count,
                mtu: 1500,
                ..ShardConfig::default()
            },
            logic_factory,
        );
        let _ = shard_wakes.set(
            (0..shard_count)
                .filter_map(|i| shards.doorbell(i))
                .collect::<Vec<_>>(),
        );

        // Hand established sessions to the host. One shared runtime,
        // one task per session: a host handler that lives as long as
        // its session (a relay's pump loop) must never occupy the
        // handoff lane, or the second long-lived flow of the process
        // would never reach its handler.
        let runtime_handler = Arc::clone(&shared.handler);
        std::thread::Builder::new()
            .name("vfawn-native-sessions".into())
            .spawn(move || {
                let workers = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
                    .min(4);
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(workers)
                    .enable_all()
                    .build()
                    .expect("session runtime");
                while let Ok(handoff) = sessions_rx.recv() {
                    let handler = Arc::clone(&runtime_handler);
                    runtime.spawn(async move {
                        let transport = NativeTcpIo {
                            events: handoff.events,
                            write_lane: Arc::clone(&handoff.write_lane),
                            shard_wake: Arc::clone(&handoff.shard_wake),
                            pending: VecDeque::new(),
                            closed: false,
                        };
                        // Establish event first: the host sees the flow
                        // as live before any bytes.
                        let session =
                            TcpSession::new(handoff.flow, Box::new(transport), handoff.tracker);
                        handler.on_tcp(session).await;
                    });
                }
            })
            .expect("spawn session thread");

        // The UDP session runtime: same shape as the TCP side — one
        // shared runtime, one task per datagram flow.
        let udp_handler = Arc::clone(&shared.handler);
        std::thread::Builder::new()
            .name("vfawn-native-udp".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("udp session runtime");
                runtime.block_on(async move {
                    while let Ok(handoff) = udp_rx.recv() {
                        let handler = Arc::clone(&udp_handler);
                        tokio::spawn(async move {
                            let transport = crate::udp_slot::NativeUdpIo {
                                events: handoff.events,
                                lane: Arc::clone(&handoff.lane),
                                lane_bytes: Arc::clone(&handoff.lane_bytes),
                                shard_wake: Arc::clone(&handoff.shard_wake),
                                origin: handoff.flow.destination,
                            };
                            let session = vfawn_core::UdpSession::new(
                                handoff.flow,
                                Box::new(transport),
                                handoff.tracker,
                            );
                            handler.on_udp(session).await;
                        });
                    }
                });
            })
            .expect("spawn udp session thread");

        // The stop watcher owns the pipeline: when the host raises the
        // handle's flag, the watcher drops the shards, whose leave
        // stops and joins every thread — and the producer's exit
        // knocks the device's I/O thread awake, so the interface
        // leaves with the pipeline instead of outliving it.
        let stop_flag = handle.stop_flag();
        std::thread::Builder::new()
            .name("vfawn-native-stop".into())
            .spawn(move || {
                while !stop_flag.load(std::sync::atomic::Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                drop(shards);
            })
            .expect("spawn stop watcher");

        Ok(handle)
    }
}

/// The cookie secret for one spawn: drawn from the clock and mixed,
/// so each process run answers SYNs with a different key (RFC 4987
/// §3.3's rotating secret, taken to process granularity).
fn flood_secret() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9);
    let mut hash = nanos ^ 0x9e37_79b9_7f4a_7c15;
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^= hash >> 31;
    hash as u32
}

/// A slot that swallows everything: for flows the native stack cannot
/// carry, and for the SYNs a full backlog refused.
struct SinkSlot;

impl SlotLogic for SinkSlot {
    fn on_packet(
        &mut self,
        _packet: &[u8],
        _out: &mut VecDeque<BytesMut>,
        _pool: &BufferPool,
        _mtu: usize,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfawn_core::{Action, IcmpPacket, TcpSession, UdpSession, Verdict};

    struct NoHandler;

    #[async_trait::async_trait]
    impl vfawn_core::SessionHandler for NoHandler {
        fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
            Verdict::Accept
        }
        async fn on_tcp(&self, _session: TcpSession) {}
        async fn on_udp(&self, _session: UdpSession) {}
        async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
            Action::Drop
        }
    }

    fn slot_with_waiting_output(bytes: &[u8]) -> TcpSlot {
        let client = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            44444,
        ));
        let server = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            443,
        ));
        let write_lane = Arc::new(std::sync::Mutex::new(WriteLane::new()));
        {
            let mut lane = write_lane.lock().expect("write lane");
            lane.bytes = bytes.len();
            lane.writes.push_back(bytes.to_vec());
        }
        let (sessions_tx, _sessions_rx) = mpsc::sync_channel(4);
        let mut slot = TcpSlot {
            connection: ServerConnection::new(1000, 1460),
            flow_key: vfawn_wire::flow::FlowKey {
                src: client.ip(),
                src_port: client.port(),
                dst: server.ip(),
                dst_port: server.port(),
                protocol: IpProtocol::Tcp,
            },
            client,
            server,
            handler: Arc::new(NoHandler),
            accept: Arc::new(std::sync::Mutex::new(AcceptQueue::new(
                true,
                64,
                Box::new(FixedSecret(0)),
            ))),
            sessions: sessions_tx,
            flow: FlowInfo {
                network: Network::Tcp,
                source: client,
                destination: server,
            },
            write_lane,
            shard_wake: Arc::new(ShardBell::new()),
            cc: Box::new(crate::congestion::Cubic::new(1460)),
            to_host: None,
            judged: false,
            refused: false,
            flight: Vec::new(),
            flight_base: 0,
            data_sent_at: None,
            data_retries: 0,
            synack_at: None,
            synack_retries: 0,
            fin_at: None,
            persist_at: None,
            persist_retries: 0,
            diag_at: None,
            diag_queued: 0,
            keepalive_at: None,
            keepalive_probes: 0,
            tracker: None,
        };
        // Drive the slot to ESTABLISHED with a handshake like the
        // machine's own tests use.
        let syn = Inbound {
            seq: 5000,
            ack: 0,
            flags: ctl::SYN,
            window: 64256,
            options: Default::default(),
            payload: &[],
        };
        let _ = slot.connection.on_segment(&syn);
        slot.connection.send_advance(1);
        let ack = Inbound {
            seq: 5001,
            ack: 1001,
            flags: ctl::ACK,
            window: 64256,
            options: Default::default(),
            payload: &[],
        };
        let _ = slot.connection.on_segment(&ack);
        slot
    }

    #[test]
    fn a_single_waiting_byte_leaves_on_the_sweep() {
        let mut slot = slot_with_waiting_output(b"x");
        let mut out: VecDeque<BytesMut> = VecDeque::new();
        slot.on_idle(&mut out);
        assert!(!out.is_empty(), "the sweep must move the waiting byte");
        assert_eq!(
            slot.write_lane.lock().expect("write lane").bytes,
            0,
            "the lane empties"
        );
    }

    #[test]
    fn bulk_waiting_output_drains_one_window_per_sweep() {
        let mut slot = slot_with_waiting_output(&[7u8; 32 * 1024]);
        let mut out: VecDeque<BytesMut> = VecDeque::new();
        slot.on_idle(&mut out);
        assert!(!out.is_empty());
        // One sweep moves one congestion window; the rest waits for
        // the acknowledgments the real wire would send.
        let left = slot.write_lane.lock().expect("write lane").bytes;
        assert!(left < 32 * 1024 && left > 0);
    }
}
