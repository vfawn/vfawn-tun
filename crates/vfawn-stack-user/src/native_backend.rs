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
use std::time::Instant;

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
use crate::native_tcp::{Inbound, Reaction, ServerConnection, TcpState, emit_v4};
use crate::shards::{BufferPool, LogicFactory, ShardConfig, Shards, SlotLogic};

/// The segment size the native stack answers with: RFC 9293 §3.7.1's
/// default for a peer that sent no MSS option. The TUN's full 1460 is
/// a bench-time knob once the differential bed grows option parsing.
const MSS: u16 = 536;

/// What a slot tells the session wrapper.
enum HostEvent {
    Established,
    Bytes(Vec<u8>),
    Closed,
}

/// The v4 endpoints of a flow, as the emitter wants them.
fn v4_ends(flow: &FlowKey) -> Option<(std::net::SocketAddrV4, std::net::SocketAddrV4)> {
    let (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) = (flow.src, flow.dst) else {
        return None;
    };
    Some((
        std::net::SocketAddrV4::new(src, flow.src_port),
        std::net::SocketAddrV4::new(dst, flow.dst_port),
    ))
}

/// One flow inside a shard: the connection, the congestion controller
/// that bounds its send side, and the host lane that earns a channel
/// only when the handshake completes.
struct TcpSlot {
    connection: ServerConnection,
    client: std::net::SocketAddrV4,
    server: std::net::SocketAddrV4,
    handler: Arc<dyn SessionHandler>,
    accept: Arc<std::sync::Mutex<AcceptQueue>>,
    sessions: mpsc::SyncSender<SessionHandoff>,
    flow: FlowInfo,
    /// The lane this slot's host writes arrive on.
    write_lane: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    cc: Box<dyn CongestionAlgo>,
    /// The host channel, created when the handshake completes. A SYN
    /// that never completes (a spoofed flood) costs nothing here.
    to_host: Option<mpsc::SyncSender<HostEvent>>,
    /// The host verdict runs once, on the flow's first segment.
    judged: bool,
    /// A rejected or dropped flow: everything after is swallowed.
    refused: bool,
}

impl TcpSlot {
    fn announce(&mut self) {
        if self.to_host.is_some() || self.connection.state() != TcpState::Established {
            return;
        }
        // The handshake completed; only now does the flow earn a
        // session. This is the accept layer's other half: state that
        // never establishes (the spoofed SYN's slot) never reaches the
        // host, never allocates channels, never spawns a task.
        let (event_tx, event_rx) = mpsc::sync_channel(1024);
        let handoff = SessionHandoff {
            flow: self.flow.clone(),
            events: event_rx,
            write_lane: Arc::clone(&self.write_lane),
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
            vfawn_core::verdict::VerdictAction::CreateSession { .. } => {}
            vfawn_core::verdict::VerdictAction::Reset => {
                // The debt the transitional backend could not pay: the
                // raw SYN is right here, so the RST is real (RFC 9293
                // §3.4, constructed from the offending segment).
                if let Some(frame) = tcp_rst_v4(packet, *self.server.ip()) {
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
        let inflight = self
            .connection
            .send_nxt()
            .wrapping_sub(self.connection.send_una());
        let mut budget = self.cc.window().saturating_sub(inflight) as usize;
        let mut lane = self.write_lane.lock().expect("write lane");
        while let Some(write) = lane.front_mut() {
            if write.is_empty() {
                // The host's shutdown marker: a FIN after any data. The
                // FIN is one byte past the stream and leaves ungated;
                // a window with no room must not wedge the close.
                lane.pop_front();
                drop(lane);
                let reaction = self.connection.fin_reaction();
                if reaction.flags != 0 {
                    let frame = emit_v4(self.server, self.client, &reaction, &[]);
                    out.push_back(BytesMut::from(&frame[..]));
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
                window: 65535,
                delivered: Vec::new(),
                held: false,
                gap_filled: false,
            };
            let frame = emit_v4(self.server, self.client, &reaction, &write[..take]);
            out.push_back(BytesMut::from(&frame[..]));
            self.connection.send_advance(take as u32);
            write.drain(..take);
            budget -= take;
            if write.is_empty() {
                lane.pop_front();
            }
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
        let Ok((ip, payload)) = Ipv4Header::parse(packet) else {
            return;
        };
        if ip.protocol != IpProtocol::Tcp {
            return;
        }
        let Ok((header, segment_payload)) = TcpHeader::parse(payload) else {
            return;
        };
        if !self.judged {
            self.judge(packet, out);
        }
        if self.refused {
            return;
        }
        let inbound = Inbound::parse(&header, segment_payload);
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
                self.cc.on_signal(
                    self.connection.mss(),
                    Signal::Acked {
                        newly: delta.min(u32::from(u16::MAX)),
                        rtt: None,
                    },
                );
            }
        }

        // Establish before delivering: the completing ACK may carry
        // data, and those bytes need the channel the handshake just
        // earned.
        self.announce();
        if let Some(to_host) = &self.to_host
            && !reaction.delivered.is_empty()
        {
            let _ = to_host.send(HostEvent::Bytes(reaction.delivered.clone()));
        }

        if reaction.flags != 0 {
            let frame = emit_v4(self.server, self.client, &reaction, &[]);
            out.push_back(BytesMut::from(&frame[..]));
            self.connection
                .send_advance(u32::from(reaction.flags & 0x03 != 0));
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
    }

    fn on_idle(&mut self, out: &mut VecDeque<BytesMut>) {
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
    events: mpsc::Receiver<HostEvent>,
    write_lane: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    pending: VecDeque<u8>,
    closed: bool,
}

#[async_trait::async_trait]
impl TcpTransport for NativeTcpIo {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.pending.is_empty() {
                let take = self.pending.len().min(buf.len());
                let bytes: Vec<u8> = self.pending.drain(..take).collect();
                buf[..take].copy_from_slice(&bytes);
                return Ok(take);
            }
            match self.events.try_recv() {
                Ok(HostEvent::Bytes(bytes)) => self.pending.extend(bytes),
                Ok(HostEvent::Established) => continue,
                Ok(HostEvent::Closed) => {
                    self.closed = true;
                    return Ok(0);
                }
                Err(mpsc::TryRecvError::Empty) => {
                    if self.closed {
                        return Ok(0);
                    }
                    // One millisecond at a time: no runtime dependency,
                    // no busy spin, and the shard wakes this within a
                    // batch of any packet arriving.
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.closed = true;
                    return Ok(0);
                }
            }
        }
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write_lane
            .lock()
            .expect("write lane")
            .push_back(data.to_vec());
        Ok(data.len())
    }

    async fn shutdown_write(&mut self) -> io::Result<()> {
        self.write_lane
            .lock()
            .expect("write lane")
            .push_back(Vec::new());
        Ok(())
    }

    async fn abort(&mut self) -> io::Result<()> {
        self.write_lane.lock().expect("write lane").clear();
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
    ) -> Arc<dyn Fn() -> Box<dyn CongestionAlgo> + Send + Sync> {
        match choice {
            vfawn_core::CongestionAlgo::Reno => Arc::new(|| Box::new(Reno::new(MSS))),
            _ => Arc::new(|| Box::new(Cubic::new(MSS))),
        }
    }
}

/// Everything the spawn path threads through the factory closure.
struct SpawnShared {
    handler: Arc<dyn SessionHandler>,
    sessions: mpsc::SyncSender<SessionHandoff>,
    accept: Arc<std::sync::Mutex<AcceptQueue>>,
    cc_factory: Arc<dyn Fn() -> Box<dyn CongestionAlgo> + Send + Sync>,
}

/// A ready session handed to the runtime side.
struct SessionHandoff {
    flow: FlowInfo,
    events: mpsc::Receiver<HostEvent>,
    write_lane: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
}

impl StackBackend for NativeBackend {
    fn spawn(
        self: Box<Self>,
        device: Box<dyn PacketDevice>,
        handler: Arc<dyn SessionHandler>,
    ) -> io::Result<StackHandle> {
        let handle = StackHandle::new();
        let write_device = device.duplicate()?;

        let (sessions_tx, sessions_rx) = mpsc::sync_channel::<SessionHandoff>(1024);
        let shared = Arc::new(SpawnShared {
            handler,
            sessions: sessions_tx,
            accept: Arc::new(std::sync::Mutex::new(AcceptQueue::new(
                self.syn_cookies,
                self.backlog,
                Box::new(FixedSecret(flood_secret())),
            ))),
            cc_factory: Self::cc_factory(self.congestion),
        });

        let factory_shared = Arc::clone(&shared);
        let logic_factory: LogicFactory = Arc::new(move |flow: &FlowKey| {
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
            let write_lane = Arc::new(std::sync::Mutex::new(VecDeque::new()));
            Box::new(TcpSlot {
                connection: ServerConnection::new(isn, MSS),
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
                cc: (factory_shared.cc_factory)(),
                to_host: None,
                judged: false,
                refused: false,
            })
        });

        let shards = Shards::start(
            device,
            write_device,
            ShardConfig {
                shards: self.shards,
                mtu: 1500,
                ..ShardConfig::default()
            },
            logic_factory,
        );

        // Hand established sessions to the host on a plain thread: the
        // contract wants `on_tcp` awaited, and nothing here needs a
        // runtime of its own.
        let runtime_handler = Arc::clone(&shared.handler);
        std::thread::Builder::new()
            .name("vfawn-native-sessions".into())
            .spawn(move || {
                // A minimal single-threaded runtime per session batch;
                // each session gets its own small context.
                while let Ok(handoff) = sessions_rx.recv() {
                    let handler = Arc::clone(&runtime_handler);
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("session runtime");
                    rt.block_on(async move {
                        let transport = NativeTcpIo {
                            events: handoff.events,
                            write_lane: Arc::clone(&handoff.write_lane),
                            pending: VecDeque::new(),
                            closed: false,
                        };
                        // Establish event first: the host sees the flow
                        // as live before any bytes.
                        let session = TcpSession::new(handoff.flow, Box::new(transport), None);
                        handler.on_tcp(session).await;
                    });
                }
            })
            .expect("spawn session thread");

        // The shards handle holds the threads; park this handle's stop
        // by leaking into a leak-box that stops on StackHandle drop is
        // the facade's business via shutdown ordering in volume two.
        // For now the threads live as long as the process, matching
        // the e2e lifecycle (start once, kill to stop).
        std::mem::forget(shards);

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
