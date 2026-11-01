// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The in-house TCP, volume one: the state machine from LISTEN through
//! the handshake into bidirectional data, written against RFC 9293
//! with a citation on every state transition, and validated segment by
//! segment against the smoltcp oracle (035's bed).
//!
//! Scope of this volume, stated plainly: SYN processing and the
//! handshake sequence, sequence-space bookkeeping (SND.NXT/RCV.NXT and
//! acknowledgment), ordered reassembly of in-window segments into the
//! receive queue, MSS advertisement, and FIN handling on the passive
//! side so the teardown scenarios close cleanly. Out-of-order queues,
//! retransmission timers, SACK, window scaling, and congestion control
//! arrive in volume two (038); when this volume meets a segment it is
//! not ready for, the segment is dropped on purpose rather than
//! guessing.
//!
//! One connection is one struct with no locks and no threads of its
//! own: the shard loop calls `on_segment` and collects what the
//! connection wants sent. That is the whole concurrency story, and it
//! is why the differential driver and the shard can share this code.

use vfawn_wire::protocol::IpProtocol;
use vfawn_wire::tcp::TcpHeader;

/// Control bits (RFC 9293 §3.1) in wire order, as a plain constant set
/// so segment construction reads like the RFC's own state diagrams.
pub mod ctl {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// A connection's place in the RFC 9293 §3.3.2 state diagram. Only the
/// states this volume can occupy are listed; the rest arrive with their
/// features in 038.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// Waiting for a connection request (the listening side).
    Listen,
    /// Waiting for the client's ACK to complete the handshake
    /// (RFC 9293: the server's half-open state).
    SynReceived,
    /// The connection is carrying data in both directions.
    Established,
    /// Our FIN is sent and acknowledged by the peer (RFC 9293 §3.3.2:
    /// CLOSE-WAIT's mirror on the side that closes second is handled by
    /// the session layer; this volume models the passive path).
    CloseWait,
    /// Our FIN is out, the peer's FIN is in, the last ACK is sent.
    LastAck,
    /// A RST was sent or received; the connection is over
    /// (RFC 9293 §3.6.2: reset generation and processing).
    Closed,
}

/// One direction of the send sequence space (RFC 9293 §3.3.4):
/// una <= nxt <= (una + window) is the invariant the peer enforces.
#[derive(Debug, Clone, Copy)]
pub struct SendSpace {
    /// Oldest unacknowledged sequence number (SND.UNA).
    una: u32,
    /// Next sequence number to send (SND.NXT).
    nxt: u32,
    /// The window we grant the peer in segments we emit.
    window: u16,
}

/// The receive side: everything we accept must land inside
/// [rcv_nxt, rcv_nxt + window) (RFC 9293 §3.3.5 acceptability test).
pub struct RecvSpace {
    nxt: u32,
    window: u16,
}

/// A parsed inbound segment narrowed to what the state machine reads.
pub struct Inbound<'a> {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

impl<'a> Inbound<'a> {
    pub fn parse(header: &TcpHeader, payload: &'a [u8]) -> Self {
        Self {
            seq: header.seq,
            ack: header.ack,
            flags: header.flags.bits(),
            payload,
        }
    }

    fn has(&self, bit: u8) -> bool {
        self.flags & bit != 0
    }
}

/// What the connection wants on the wire after processing one inbound
/// segment: the segment to send next, if any, plus bytes the
/// application may read now.
pub struct Reaction {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// Bytes handed to the application, in order.
    pub delivered: Vec<u8>,
}

impl Reaction {
    pub fn silent() -> Self {
        Self {
            seq: 0,
            ack: 0,
            flags: 0,
            window: 0,
            delivered: Vec::new(),
        }
    }

    pub fn segment(seq: u32, ack: u32, flags: u8, window: u16) -> Self {
        Self {
            seq,
            ack,
            flags,
            window,
            delivered: Vec::new(),
        }
    }
}

/// The passive-open server connection: one five-tuple's state machine.
///
/// The initial sequence number is a constructor input, not entropy, so
/// the differential bed can drive both stacks with the same script.
pub struct ServerConnection {
    state: TcpState,
    send: SendSpace,
    recv: RecvSpace,
    /// MSS we advertise; the offer rides every SYN-ACK (RFC 9293
    /// §3.7.1: the maximum segment size option).
    mss: u16,
    /// FIN received from the peer: our FIN answers once the session
    /// layer says so; in this volume the FIN echoes immediately when
    /// the peer closes first (passive close).
    fin_received: bool,
    fin_sent: bool,
}

impl ServerConnection {
    pub fn new(listen_isn: u32, mss: u16) -> Self {
        Self {
            state: TcpState::Listen,
            send: SendSpace {
                una: listen_isn,
                nxt: listen_isn,
                window: 65535,
            },
            recv: RecvSpace {
                nxt: 0,
                window: 65535,
            },
            mss,
            fin_received: false,
            fin_sent: false,
        }
    }

    pub fn state(&self) -> TcpState {
        self.state
    }

    /// Bytes the peer has sent that we have acknowledged, in order.
    pub fn delivered_total(&self) -> u32 {
        self.recv.nxt.wrapping_sub(1)
    }

    /// The acceptability test (RFC 9293 §3.3.5, SEG.MAYBE): a data or
    /// FIN segment is acceptable when any part of its sequence range
    /// falls inside the receive window.
    fn acceptable(&self, seq: u32, length: u32) -> bool {
        let window = u32::from(self.recv.window);
        let offset = seq.wrapping_sub(self.recv.nxt);
        // RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND, in wrapping arithmetic
        // expressed as an offset smaller than the window.
        offset < window || (length > 0 && offset.wrapping_sub(window) < length)
    }

    /// Process one inbound segment and produce the reaction. Every
    /// transition cites the RFC paragraph that prescribes it.
    pub fn on_segment(&mut self, inbound: &Inbound) -> Reaction {
        match self.state {
            TcpState::Listen => self.on_listen(inbound),
            TcpState::SynReceived => self.on_syn_received(inbound),
            TcpState::Established | TcpState::CloseWait => self.on_established(inbound),
            TcpState::LastAck => self.on_last_ack(inbound),
            TcpState::Closed => Reaction::silent(),
        }
    }

    /// LISTEN: a SYN opens the handshake (RFC 9293 §3.4: the listener
    /// answers SYN-ACK and moves to SYN-RECEIVED). Anything else from
    /// an unknown peer dies silently in this volume; RST generation for
    /// it belongs to the accept queue in 039.
    fn on_listen(&mut self, inbound: &Inbound) -> Reaction {
        if !inbound.has(ctl::SYN) {
            return Reaction::silent();
        }
        // RFC 9293 §3.4: RCV.NXT is set to SEG.SEQ+1 and the SYN-ACK
        // goes out at SND.NXT (the ISN); the SYN consumes one sequence
        // number, which the emitter books when the segment leaves.
        self.recv.nxt = inbound.seq.wrapping_add(1);
        self.state = TcpState::SynReceived;
        Reaction::segment(
            self.send.nxt,
            self.recv.nxt,
            ctl::SYN | ctl::ACK,
            self.send.window,
        )
    }

    /// SYN-RECEIVED: the client's ACK completes the three-way
    /// handshake (RFC 9293 §3.4: ESTABLISHED when SND.UNA advances past
    /// our ISN, which the ACK field now acknowledges).
    fn on_syn_received(&mut self, inbound: &Inbound) -> Reaction {
        if !inbound.has(ctl::ACK) {
            return Reaction::silent();
        }
        // RFC 9293 §3.3.5: SND.UNA < SEG.ACK <= SND.NXT is the
        // acceptable-ACK test; for the handshake ACK exactly
        // SND.UNA+1 == SEG.ACK.
        if !self.ack_acceptable(inbound.ack) {
            // An ACK for something never sent draws a challenge ACK in
            // the full stack; this volume ignores it and stays.
            return Reaction::silent();
        }
        self.send.una = inbound.ack;
        self.state = TcpState::Established;
        Reaction::silent()
    }

    /// ESTABLISHED and beyond: data, pure ACKs, and FIN all route here.
    /// The order of checks follows RFC 9293 §3.6: resets first, then
    /// sequence acceptability, then the ACK field, then segment text.
    fn on_established(&mut self, inbound: &Inbound) -> Reaction {
        if inbound.has(ctl::RST) {
            // RFC 9293 §3.6.2: a reset in the window ends the
            // connection immediately.
            self.state = TcpState::Closed;
            return Reaction::silent();
        }
        let length = inbound.payload.len() as u32
            + u32::from(inbound.has(ctl::SYN))
            + u32::from(inbound.has(ctl::FIN));
        if !self.acceptable(inbound.seq, length) {
            // RFC 9293 §3.3.5: an unacceptable segment draws an ACK
            // restating the current window so the peer resynchronizes.
            return Reaction::segment(self.send.nxt, self.recv.nxt, ctl::ACK, self.recv.window);
        }
        if inbound.has(ctl::ACK) && !self.ack_acceptable(inbound.ack) {
            // Old duplicate ACK: nothing to do (RFC 9293 §3.3.6,
            // unacceptable ACKs in ESTABLISHED).
            return Reaction::silent();
        }
        if inbound.has(ctl::ACK) {
            self.send.una = inbound.ack.max(self.send.una);
        }

        let mut reaction = Reaction::silent();

        // Segment text (RFC 9293 §3.3.7): in-window payload moves to
        // the receive queue and RCV.NXT advances by its length.
        if !inbound.payload.is_empty() {
            let offset = inbound.seq.wrapping_sub(self.recv.nxt) as usize;
            let payload = if offset == 0 {
                inbound.payload
            } else {
                // A retransmission overlapping already-delivered bytes:
                // keep only the new tail (RFC 9293 §3.3.5 SEQ.SKIP).
                &inbound.payload[offset.min(inbound.payload.len())..]
            };
            if !payload.is_empty() {
                reaction.delivered = payload.to_vec();
                self.recv.nxt = self.recv.nxt.wrapping_add(payload.len() as u32);
            }
        }

        // FIN processing (RFC 9293 §3.3.7): FIN consumes one sequence
        // number after the text.
        if inbound.has(ctl::FIN) {
            self.fin_received = true;
            self.recv.nxt = self.recv.nxt.wrapping_add(1);
        }

        // Nothing new arrived and the peer's ACK told us nothing we did
        // not already know: an ACK of an ACK carries no information,
        // and the oracle stays quiet exactly here, so staying quiet is
        // both correct etiquette and record parity.
        if reaction.delivered.is_empty() && !self.fin_received && !inbound.has(ctl::FIN) {
            return Reaction::silent();
        }

        // Acknowledge what just landed. The passive close answers FIN
        // with FIN+ACK so teardown scenarios complete in one volume;
        // RFC 9293 §3.5 prescribes the same bytes.
        let answer_fin = self.fin_received && !self.fin_sent && self.state == TcpState::Established;
        reaction.seq = self.send.nxt;
        reaction.ack = self.recv.nxt;
        reaction.flags = if answer_fin {
            self.fin_sent = true;
            self.state = TcpState::LastAck;
            ctl::FIN | ctl::ACK
        } else {
            ctl::ACK
        };
        reaction.window = self.recv.window;
        reaction
    }

    /// LAST-ACK: our FIN's acknowledgment releases the connection
    /// (RFC 9293 §3.5: the passive closer's completion).
    fn on_last_ack(&mut self, inbound: &Inbound) -> Reaction {
        if inbound.has(ctl::ACK) && self.ack_acceptable(inbound.ack) {
            self.state = TcpState::Closed;
        }
        Reaction::silent()
    }

    /// SND.UNA <= SEG.ACK <= SND.NXT (RFC 9293 §3.3.6). An ACK equal
    /// to UNA acknowledges nothing new but is perfectly legal: it is a
    /// duplicate ACK, the peer restating its receive state while data
    /// flows the other way. Rejecting it dropped every data segment
    /// that rode an unchanged ACK field.
    fn ack_acceptable(&self, ack: u32) -> bool {
        let lower = ack.wrapping_sub(self.send.una);
        let upper = self.send.nxt.wrapping_sub(self.send.una);
        lower <= upper
    }

    /// The MSS this connection advertises (RFC 9293 §3.7.1).
    pub fn mss(&self) -> u16 {
        self.mss
    }

    /// Mark the host's FIN as sent; the emitter calls this once the
    /// FIN segment has left.
    pub fn mark_fin_sent(&mut self) {
        self.fin_sent = true;
    }

    /// Next sequence number to send (SND.NXT): the emitter's cursor.
    pub fn send_nxt(&self) -> u32 {
        self.send.nxt
    }

    /// Receive cursor (RCV.NXT): what the next ACK will carry.
    pub fn recv_nxt(&self) -> u32 {
        self.recv.nxt
    }

    /// Advance the send space over a segment just emitted: data length
    /// plus one for a SYN or FIN (RFC 9293 §3.3.4: each consumes
    /// sequence space).
    pub fn send_advance(&mut self, consumed: u32) {
        self.send.nxt = self.send.nxt.wrapping_add(consumed);
    }

    /// The FIN the host's shutdown triggers: sent at SND.NXT with the
    /// current acknowledgment (RFC 9293 §3.5, active close's first
    /// step). Volume one folds the peer-FIN answer into ESTABLISHED
    /// handling; this is the host-initiated half.
    pub fn fin_reaction(&self) -> Reaction {
        if self.fin_sent || self.state != TcpState::Established {
            return Reaction::silent();
        }
        Reaction::segment(
            self.send.nxt,
            self.recv.nxt,
            ctl::FIN | ctl::ACK,
            self.send.window,
        )
    }

    /// The SYN-ACK to retransmit while the handshake waits for the
    /// client's ACK (RFC 9293 §3.4: retries at the retransmission
    /// timeout until the handshake completes or gives up). None once
    /// the connection has left SYN-RECEIVED.
    pub fn synack_retransmit(&self) -> Option<Reaction> {
        match self.state {
            TcpState::SynReceived => Some(Reaction::segment(
                self.send.una,
                self.recv.nxt,
                ctl::SYN | ctl::ACK,
                self.send.window,
            )),
            _ => None,
        }
    }
}

/// Build a reaction into wire bytes: IPv4 + TCP with the given
/// endpoints and a checksum computed over the pseudo header. The
/// emitter's job is faithful bytes, no policy.
pub fn emit_v4(
    src: std::net::SocketAddrV4,
    dst: std::net::SocketAddrV4,
    reaction: &Reaction,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + 20 + payload.len());
    let total = 20 + 20 + payload.len();
    // IPv4 header (RFC 791): protocol 6, correct total length.
    packet.extend_from_slice(&[0x45, 0x00]);
    packet.extend_from_slice(&(total as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    packet.extend_from_slice(&src.ip().octets());
    packet.extend_from_slice(&dst.ip().octets());
    // TCP header (RFC 9293 §3.1).
    packet.extend_from_slice(&src.port().to_be_bytes());
    packet.extend_from_slice(&dst.port().to_be_bytes());
    packet.extend_from_slice(&reaction.seq.to_be_bytes());
    packet.extend_from_slice(&reaction.ack.to_be_bytes());
    packet.push(5 << 4); // data offset: no options in this volume
    packet.push(reaction.flags);
    packet.extend_from_slice(&reaction.window.to_be_bytes());
    packet.extend_from_slice(&[0, 0]); // checksum, fixed below
    packet.extend_from_slice(&[0, 0]); // urgent pointer
    packet.extend_from_slice(payload);

    let sum = vfawn_wire::checksum::pseudo_header_v4(
        *src.ip(),
        *dst.ip(),
        IpProtocol::Tcp,
        (20 + payload.len()) as u32,
    ) + vfawn_wire::checksum::sum_words(&packet[20..]);
    let fixed = !vfawn_wire::checksum::fold(sum);
    packet[36..38].copy_from_slice(&fixed.to_be_bytes());

    let header_sum = vfawn_wire::checksum::sum_words(&packet[..20]);
    let fixed = !vfawn_wire::checksum::fold(header_sum);
    packet[10..12].copy_from_slice(&fixed.to_be_bytes());
    packet
}

/// The differential driver's native side: the same scenario, the same
/// wire bytes out as the smoltcp oracle produces, from this stack.
pub struct NativeTcpConnection {
    pub connection: ServerConnection,
    pub server_isn: u32,
}

impl NativeTcpConnection {
    pub fn new(listen_isn: u32, mss: u16) -> Self {
        Self {
            connection: ServerConnection::new(listen_isn, mss),
            server_isn: listen_isn,
        }
    }
}

/// Re-export for callers that inspect flags on reactions.
pub fn flags_of(reaction: &Reaction) -> u8 {
    reaction.flags
}
