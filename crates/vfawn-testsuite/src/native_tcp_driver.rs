// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The player side: the in-house TCP driven through the same
//! [`StackDriver`] contract the smoltcp oracle implements, so the 035
//! corpus runs against both without a single scenario changing.
//!
//! One connection per scenario (the corpus is single-flow), a fixed
//! listen ISN so both stacks see the same acknowledgment space, and the
//! echo application mirroring the oracle's: whatever a segment
//! delivers is written back, so data flowing both directions is part
//! of every comparison.

use std::collections::VecDeque;

use vfawn_stack_user::native_tcp::{Inbound, NativeTcpConnection, Reaction, emit_v4};
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::protocol::IpProtocol;
use vfawn_wire::tcp::TcpHeader;

use crate::diff::{Scenario, SegmentRecord, StackDriver, Step};

/// The default maximum segment size when the peer offers no MSS
/// option (RFC 9293 §3.7.1: 536 octets for IPv4); the corpus SYNs
/// carry no options, and the oracle chunks by the same default.
pub const DEFAULT_MSS: u16 = 536;

/// The listen ISN is a constructor input, not entropy: the differential
/// bed probes the oracle's ISN once and hands the same value here, so
/// both stacks live in one acknowledgment space. The shard integration
/// (037's backend) injects its own policy when the time comes.
pub const DEFAULT_LISTEN_ISN: u32 = 1000;

pub struct NativeTcpDriver {
    connection: NativeTcpConnection,
    /// When the current SYN-ACK left, for handshake retransmission.
    synack_at: Option<u64>,
    /// How many times the SYN-ACK has been retransmitted; drives the
    /// exponential backoff.
    synack_retries: u32,
    /// The send buffer as one contiguous stream from `flight_base`
    /// (the send sequence space of RFC 9293 §3.3.4): application
    /// writes append, acknowledgments prune the front, and the RTO
    /// resends MSS-sized pieces from the base, exactly how a socket
    /// send buffer behaves.
    flight: Vec<u8>,
    flight_base: u32,
    /// When the earliest in-flight chunk was (re)sent, and how many
    /// retries have happened (the timeout doubles per retry, §5).
    data_sent_at: Option<u64>,
    data_retries: u32,
    /// The scenario's endpoints, for emitting wire bytes.
    server: std::net::SocketAddrV4,
    client: std::net::SocketAddrV4,
    /// Application bytes acknowledged but not yet sent back.
    echo_backlog: VecDeque<Vec<u8>>,
    now_ms: u64,
}

impl NativeTcpDriver {
    pub fn new() -> Self {
        Self::with_listen_isn(DEFAULT_LISTEN_ISN)
    }

    pub fn with_listen_isn(listen_isn: u32) -> Self {
        Self {
            connection: NativeTcpConnection::new(listen_isn, DEFAULT_MSS),
            synack_at: None,
            synack_retries: 0,
            flight: Vec::new(),
            flight_base: 0,
            data_sent_at: None,
            data_retries: 0,
            server: std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
            client: std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
            echo_backlog: VecDeque::new(),
            now_ms: 0,
        }
    }
}

impl Default for NativeTcpDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl StackDriver for NativeTcpDriver {
    fn finish(&mut self) -> Vec<SegmentRecord> {
        self.finish_drain()
    }

    fn reset(&mut self, scenario: &Scenario) {
        let listen_isn = self.connection.server_isn;
        self.connection = NativeTcpConnection::new(listen_isn, DEFAULT_MSS);
        self.server = scenario.server;
        self.client = scenario.client;
        self.echo_backlog.clear();
        self.synack_at = None;
        self.synack_retries = 0;
        self.flight.clear();
        self.flight_base = 0;
        self.data_sent_at = None;
        self.data_retries = 0;
        self.now_ms = 0;
    }

    fn step(&mut self, step: &Step) -> Vec<SegmentRecord> {
        match step {
            Step::Inject { delay_ms, packet } => {
                self.now_ms += delay_ms;
                let reaction = self.consume(packet);
                self.react(reaction)
            }
            Step::Wait { delay_ms } => {
                self.now_ms += delay_ms;
                let mut records = self.timer_fired();
                records.extend(self.data_retransmit_fired());
                records
            }
        }
    }
}

/// Whether the reaction is nothing but an acknowledgment.
fn ctl_ack_only(flags: u8) -> bool {
    flags == 0x10
}

impl NativeTcpDriver {
    /// The handshake retry (RFC 9293 §3.4): a SYN-ACK unanswered for
    /// the retransmission timeout is sent again. One second is the
    /// initial RTO (RFC 6298 §2), matching the oracle's behavior while
    /// volume two's full timer machinery is still ahead.
    fn timer_fired(&mut self) -> Vec<SegmentRecord> {
        let Some(reaction) = self.connection.connection.synack_retransmit() else {
            return Vec::new();
        };
        let Some(sent_at) = self.synack_at else {
            return Vec::new();
        };
        // RFC 6298 §5: every retransmission doubles the timeout, so a
        // one-second first retry becomes two, then four; the oracle
        // follows the same backoff.
        let threshold = 1000u64 << self.synack_retries;
        if self.now_ms.saturating_sub(sent_at) < threshold {
            return Vec::new();
        }
        self.synack_retries += 1;
        self.synack_at = Some(self.now_ms);
        let frame = emit_v4(self.server, self.client, &reaction, &[]);
        self.record_of(&frame).into_iter().collect()
    }

    /// Data retransmission on the RTO (RFC 6298 §3): when unacked
    /// data exists and the timeout elapsed, the earliest outstanding
    /// bytes go out again. One second initial, doubling per retry
    /// (§5), matching the oracle's visible behavior.
    fn data_retransmit_fired(&mut self) -> Vec<SegmentRecord> {
        if self.flight.is_empty() {
            self.data_sent_at = None;
            self.data_retries = 0;
            return Vec::new();
        }
        let Some(sent_at) = self.data_sent_at else {
            self.data_sent_at = Some(self.now_ms);
            return Vec::new();
        };
        let threshold = 1000u64 << self.data_retries;
        if self.now_ms.saturating_sub(sent_at) < threshold {
            return Vec::new();
        }
        self.data_retries += 1;
        self.data_sent_at = Some(self.now_ms);

        // Resend from the earliest unacknowledged byte in MSS-sized
        // pieces (RFC 6298 §3 over the byte stream, not per write):
        // application writes that arrived between segments have
        // coalesced here, exactly like the oracle's socket buffer.
        let mut records = Vec::new();
        let mss = self.connection.connection.mss() as usize;
        let mut offset = 0usize;
        while offset < self.flight.len() {
            let take = (self.flight.len() - offset).min(mss);
            let more_after = offset + take < self.flight.len();
            let reaction = Reaction {
                seq: self.flight_base.wrapping_add(offset as u32),
                ack: self.connection.connection.recv_nxt(),
                flags: if more_after { 0x10 } else { 0x18 },
                window: 65535,
                delivered: Vec::new(),
                held: false,
                gap_filled: false,
            };
            let frame = emit_v4(
                self.server,
                self.client,
                &reaction,
                &self.flight[offset..offset + take],
            );
            if let Some(record) = self.record_of(&frame) {
                records.push(record);
            }
            offset += take;
        }
        records
    }

    /// Mirror the oracle's post-scenario drain: late timers speak
    /// before the comparison is judged.
    pub fn finish_drain(&mut self) -> Vec<SegmentRecord> {
        let mut records = Vec::new();
        for _ in 0..4 {
            self.now_ms += 250;
            records.extend(self.timer_fired());
            records.extend(self.data_retransmit_fired());
        }
        records
    }

    /// Parse one packet, hand its TCP part to the connection, queue the
    /// echo of anything delivered.
    fn consume(&mut self, packet: &[u8]) -> Reaction {
        let Ok((ip, payload)) = Ipv4Header::parse(packet) else {
            return Reaction::silent();
        };
        if ip.protocol != IpProtocol::Tcp {
            return Reaction::silent();
        }
        let Ok((header, segment_payload)) = TcpHeader::parse(payload) else {
            return Reaction::silent();
        };
        let inbound = Inbound::parse(&header, segment_payload);
        let reaction = self.connection.connection.on_segment(&inbound);
        // Prune by what the connection actually accepted (SND.UNA),
        // never by the raw ACK field: an acknowledgment beyond what was
        // sent moves nothing (RFC 9293 §3.3.6), and honoring it would
        // drop data the wire still owes.
        let una = self.connection.connection.send_una();
        if !self.flight.is_empty() {
            let end = self.flight_base.wrapping_add(self.flight.len() as u32);
            let fully_acked = una == end || una.wrapping_sub(end) < u32::MAX / 2;
            if fully_acked {
                self.flight.clear();
                self.data_sent_at = None;
                self.data_retries = 0;
            } else if una.wrapping_sub(self.flight_base) < u32::MAX / 2 {
                let drop = (una.wrapping_sub(self.flight_base) as usize).min(self.flight.len());
                self.flight.drain(..drop);
                self.flight_base = una;
            }
        }
        if reaction.flags & 0x12 == 0x12 && reaction.delivered.is_empty() {
            self.synack_at = Some(self.now_ms);
        }
        if !reaction.delivered.is_empty() {
            self.echo_backlog.push_back(reaction.delivered.clone());
        }
        reaction
    }

    /// Turn the connection's reaction into wire bytes, then send the
    /// echo backlog behind it as data segments.
    fn react(&mut self, reaction: Reaction) -> Vec<SegmentRecord> {
        let mut records = Vec::new();

        // The reaction itself (SYN-ACK, FIN-ACK, or a pure ACK). When
        // the echo has bytes to send, the data segment carries the
        // acknowledgment itself and the bare ACK is folded away: the
        // oracle coalesces exactly the same way, and a stream of
        // empty ACKs ahead of data would diverge record-for-record.
        let send = reaction;
        let echo_pending = !self.echo_backlog.is_empty();
        let bare_ack_only = ctl_ack_only(send.flags);
        // A duplicate acknowledgment for a held segment is a signal the
        // sender retransmit now; delaying it behind queued data would
        // stall the gap fill, so it never folds.
        let immediate = (send.held || send.gap_filled) && bare_ack_only;
        if send.flags != 0 && (immediate || !(echo_pending && bare_ack_only)) {
            let frame = emit_v4(self.server, self.client, &send, &[]);
            if let Some(record) = self.record_of(&frame) {
                records.push(record);
            }
            // A SYN or FIN consumes one sequence number as it leaves
            // (RFC 9293 §3.3.4).
            let consumed = u32::from(send.flags & 0x03 != 0);
            self.connection.connection.send_advance(consumed);
        }

        // The echo application: backlog bytes leave as data segments
        // carrying ACKs, MSS-sized.
        while let Some(chunk) = self.echo_backlog.pop_front() {
            let mut remaining = chunk.as_slice();
            while !remaining.is_empty() {
                let take = remaining
                    .len()
                    .min(self.connection.connection.mss() as usize);
                let data = &remaining[..take];
                // PSH rides the final chunk of the application write
                // only (the oracle pushes once per write, not per
                // segment); earlier chunks are plain data-carrying ACKs.
                let more_after = remaining.len() > take || !self.echo_backlog.is_empty();
                let send = Reaction {
                    seq: self.connection.connection.send_nxt(),
                    ack: self.connection.connection.recv_nxt(),
                    flags: if more_after { 0x10 } else { 0x18 },
                    window: 65535,
                    delivered: Vec::new(),
                    held: false,
                    gap_filled: false,
                };
                let frame = emit_v4(self.server, self.client, &send, data);
                if let Some(record) = self.record_of(&frame) {
                    records.push(record);
                }
                // The send buffer grows with what the application wrote;
                // the RTO is armed over the earliest unacknowledged byte
                // (RFC 6298 §2).
                if self.flight.is_empty() {
                    self.flight_base = send.seq;
                }
                self.flight.extend_from_slice(data);
                self.data_sent_at = Some(self.now_ms);
                self.data_retries = 0;
                self.connection.connection.send_advance(take as u32);
                remaining = &remaining[take..];
            }
        }

        records
    }

    fn record_of(&self, frame: &[u8]) -> Option<SegmentRecord> {
        let (ip, payload) = Ipv4Header::parse(frame).ok()?;
        if ip.protocol != IpProtocol::Tcp {
            return None;
        }
        let (tcp, seg_payload) = TcpHeader::parse(payload).ok()?;
        Some(SegmentRecord {
            at_ms: self.now_ms,
            seq: tcp.seq,
            ack: tcp.ack,
            flags: tcp.flags.bits(),
            window: tcp.window,
            payload_len: seg_payload.len(),
        })
    }
}
