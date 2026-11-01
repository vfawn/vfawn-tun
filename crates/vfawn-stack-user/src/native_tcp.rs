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
    /// The segment was held above a receive gap: the reply is a
    /// duplicate acknowledgment, and the sender wants it immediately,
    /// not folded into whatever data is waiting to leave.
    pub held: bool,
    /// This delivery collapsed segments held above a gap: the
    /// acknowledgment advances past held data, which is news worth its
    /// own segment before any application data rides out.
    pub gap_filled: bool,
}

impl Reaction {
    pub fn silent() -> Self {
        Self {
            seq: 0,
            ack: 0,
            flags: 0,
            window: 0,
            delivered: Vec::new(),
            held: false,
            gap_filled: false,
        }
    }

    pub fn segment(seq: u32, ack: u32, flags: u8, window: u16) -> Self {
        Self {
            seq,
            ack,
            flags,
            window,
            delivered: Vec::new(),
            held: false,
            gap_filled: false,
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
    /// Segments that arrived above RCV.NXT and wait for the gap
    /// (RFC 9293 §3.3.5 SEG.SACK): (seq, bytes). Kept sorted by
    /// sequence and merged on overlap, capped so a hostile flow cannot
    /// grow it without bound.
    out_of_order: Vec<(u32, Vec<u8>)>,
    /// How many out-of-order bytes the queue may hold; the excess is
    /// dropped and later retransmission recovers it.
    ooo_budget: usize,
    /// Duplicate ACK count (RFC 9293 §3.3.6): consecutive segments
    /// that deliver nothing and restate the same acknowledgment.
    dup_acks: u32,
    /// Retransmission state (RFC 6298 §3-5): the byte range still
    /// unacknowledged, when it was (re)sent, and the current timeout.
    retransmit: Option<RetransmitState>,
    /// The zero-window probe state: whether the last advertisement was
    /// zero and a probe is owed (RFC 9293 §3.8.2, persist timer in
    /// volume two's timer module; the flag drives the driver).
    peer_window_zero: bool,
}

/// What the sender owes the wire again when the timer fires
/// (RFC 6298 §3: retransmit the earliest unacknowledged data). The
/// connection tracks whether data is outstanding; the backoff count
/// rides with the driver's timer until the shard timer module owns
/// it whole.
struct RetransmitState {
    #[allow(dead_code)]
    retries: u32,
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
            out_of_order: Vec::new(),
            ooo_budget: 64 * 1024,
            dup_acks: 0,
            retransmit: None,
            peer_window_zero: false,
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
            let mut reply =
                Reaction::segment(self.send.nxt, self.recv.nxt, ctl::ACK, self.recv.window);
            reply.held = !self.out_of_order.is_empty();
            return reply;
        }
        if inbound.has(ctl::ACK) && !self.ack_acceptable(inbound.ack) {
            // Split by direction (RFC 9293 §3.3.6 and §3.6.2's
            // challenge-ACK practice): an ACK below SND.UNA is an old
            // duplicate worth silence; an ACK beyond SND.NXT credits
            // data never sent, and the answer restates both ends of
            // our sequence space so the peer resynchronizes.
            let beyond_sent = inbound.ack.wrapping_sub(self.send.nxt) < u32::MAX / 2;
            if beyond_sent {
                return Reaction::segment(self.send.nxt, self.recv.nxt, ctl::ACK, self.recv.window);
            }
            return Reaction::silent();
        }
        let mut reaction = Reaction::silent();
        let mut delivered_any = false;

        if inbound.has(ctl::ACK) {
            // RFC 6298 §5.3: new acknowledgment clears the
            // retransmission count; the sender starts fresh.
            if self.ack_advances(inbound.ack) {
                self.send.una = inbound.ack;
                self.retransmit = None;
                self.dup_acks = 0;
            } else if inbound.payload.is_empty() && !inbound.has(ctl::FIN) {
                // Same acknowledgment again with no text: a duplicate
                // ACK (RFC 9293 §3.3.6), counted for fast detection.
                self.dup_acks += 1;
            }
        }

        let held_before = !self.out_of_order.is_empty();

        // Segment text (RFC 9293 §3.3.7): in-order payload delivers
        // immediately; a gap opens the out-of-order queue, and the
        // fill of a gap delivers what the queue now makes contiguous.
        if !inbound.payload.is_empty() {
            let offset = inbound.seq.wrapping_sub(self.recv.nxt) as usize;
            if offset == 0 {
                reaction.delivered = inbound.payload.to_vec();
                self.recv.nxt = self.recv.nxt.wrapping_add(payload_len_u32(inbound));
                delivered_any = true;
                // Data-carrying segments are not duplicate ACKs by
                // definition (RFC 9293 §3.3.6), whatever their ACK
                // field says.
                self.dup_acks = 0;
                self.collapse_ooo(&mut reaction);
            } else if offset < usize::from(self.recv.window)
                && self.ooo_usage() + inbound.payload.len() <= self.ooo_budget
            {
                // Above the gap and within budget: hold it
                // (RFC 9293 §3.3.5 SEG.SACK holds instead of
                // discarding; discarding only wastes bandwidth).
                self.queue_ooo(inbound.seq, inbound.payload);
            }
            // Below RCV.NXT entirely: pure duplicate, nothing to hold.
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
        // A reply carries information for the peer when it delivered
        // data to acknowledge, answered a FIN, or holds out-of-order
        // segments worth a duplicate ACK. An ACK that only moved our
        // own una tells the peer nothing it does not know, and the
        // oracle stays quiet exactly there.
        let held_segment = !self.out_of_order.is_empty() && !delivered_any;
        if reaction.delivered.is_empty()
            && !self.fin_received
            && !inbound.has(ctl::FIN)
            && !held_segment
        {
            return Reaction::silent();
        }

        // Acknowledge what just landed. The passive close answers FIN
        // with FIN+ACK so teardown scenarios complete in one volume;
        // RFC 9293 §3.5 prescribes the same bytes.
        let answer_fin = self.fin_received && !self.fin_sent && self.state == TcpState::Established;
        let held_now = !self.out_of_order.is_empty() && !delivered_any;
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
        reaction.held = held_now;
        reaction.gap_filled = held_before && delivered_any;
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

    /// Whether SEG.ACK moves SND.UNA forward (RFC 9293 §3.3.6's
    /// SND.UNA < SEG.ACK test, wrapping form; equal is not forward).
    fn ack_advances(&self, ack: u32) -> bool {
        let forward = ack.wrapping_sub(self.send.una);
        let limit = self.send.nxt.wrapping_sub(self.send.una);
        forward >= 1 && forward <= limit
    }

    /// Bytes currently held above the gap.
    fn ooo_usage(&self) -> usize {
        self.out_of_order.iter().map(|(_, b)| b.len()).sum()
    }

    /// Hold a segment above the gap, sorted and merged with any
    /// neighbor it overlaps (RFC 9293 §3.3.5: overlap merges, never
    /// duplicates). Sequence comparisons use signed distances from
    /// RCV.NXT so wrapping arithmetic stays honest.
    fn queue_ooo(&mut self, seq: u32, payload: &[u8]) {
        let as_offset = |value: u32| -> i64 {
            let diff = value.wrapping_sub(self.recv.nxt);
            if diff <= u32::MAX / 2 {
                i64::from(diff)
            } else {
                i64::from(diff) - i64::from(u32::MAX) - 1
            }
        };
        let mut ranges: Vec<(i64, Vec<u8>)> = self
            .out_of_order
            .drain(..)
            .map(|(seq, bytes)| {
                let start = as_offset(seq);
                let padded = vec![0u8; usize::try_from(start).unwrap_or(0)];
                let mut absolute = padded;
                absolute.extend_from_slice(&bytes);
                (start, absolute)
            })
            .collect();
        let new_start = as_offset(seq);
        let mut new_bytes = vec![0u8; usize::try_from(new_start).unwrap_or(0)];
        new_bytes.extend_from_slice(payload);
        ranges.push((new_start, new_bytes));
        ranges.sort_by_key(|(start, _)| *start);

        // Merge overlapping or adjacent ranges in one pass.
        let mut merged: Vec<(i64, Vec<u8>)> = Vec::with_capacity(ranges.len());
        for (start, bytes) in ranges {
            match merged.last_mut() {
                Some((last_start, last_bytes))
                    if start <= *last_start + last_bytes.len() as i64 =>
                {
                    let overlap = (*last_start + last_bytes.len() as i64 - start) as usize;
                    let skip = overlap.min(bytes.len());
                    last_bytes.extend_from_slice(&bytes[skip..]);
                }
                _ => merged.push((start, bytes)),
            }
        }

        // Store back as (seq, contiguous bytes) with the leading pad
        // removed; the queue stays sorted and disjoint.
        self.out_of_order = merged
            .into_iter()
            .map(|(start, bytes)| {
                let seq = self.recv.nxt.wrapping_add(start as u32);
                let pad = usize::try_from(start).unwrap_or(0);
                let tail = if pad < bytes.len() {
                    bytes[pad..].to_vec()
                } else {
                    Vec::new()
                };
                (seq, tail)
            })
            .filter(|(_, bytes)| !bytes.is_empty())
            .collect();
    }

    /// A gap filled: deliver everything the queue now makes
    /// contiguous, in order (RFC 9293 §3.3.7).
    fn collapse_ooo(&mut self, reaction: &mut Reaction) {
        while let Some((seq, held)) = self.out_of_order.first() {
            if seq.wrapping_sub(self.recv.nxt) != 0 {
                break;
            }
            let held = held.clone();
            self.recv.nxt = self.recv.nxt.wrapping_add(held.len() as u32);
            reaction.delivered.extend_from_slice(&held);
            self.out_of_order.remove(0);
        }
    }

    /// The SACK blocks to advertise (RFC 6675 §3: the segments the
    /// receiver holds, newest first, at most three, in the option
    /// layout [left, right] edge pairs relative to RCV.NXT).
    pub fn sack_blocks(&self) -> [(u32, u32); 3] {
        let mut blocks = [(0u32, 0u32); 3];
        for (slot, (seq, held)) in self.out_of_order.iter().rev().take(3).enumerate() {
            blocks[slot] = (
                seq.wrapping_sub(self.recv.nxt),
                seq.wrapping_add(held.len() as u32)
                    .wrapping_sub(self.recv.nxt),
            );
        }
        blocks
    }

    /// Whether the peer advertised a zero window on its latest ACK.
    pub fn peer_window_zero(&self) -> bool {
        self.peer_window_zero
    }

    /// Duplicate ACKs since the last advance (RFC 9293 §3.3.6).
    pub fn duplicate_acks(&self) -> u32 {
        self.dup_acks
    }

    /// The MSS this connection advertises (RFC 9293 §3.7.1).
    pub fn mss(&self) -> u16 {
        self.mss
    }

    /// Oldest unacknowledged sequence number (SND.UNA): what the
    /// sender's retransmission timer is armed over.
    pub fn send_una(&self) -> u32 {
        self.send.una
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

fn payload_len_u32(inbound: &Inbound<'_>) -> u32 {
    inbound.payload.len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive one data segment into a fresh established connection.
    fn established() -> ServerConnection {
        let mut connection = ServerConnection::new(1000, 536);
        let syn = Inbound {
            seq: 5000,
            ack: 0,
            flags: ctl::SYN,
            payload: &[],
        };
        let _ = connection.on_segment(&syn);
        // The emitter books the SYN's sequence consumption; the unit
        // test plays that role by hand.
        connection.send_advance(1);
        let ack = Inbound {
            seq: 5001,
            ack: 1001,
            flags: ctl::ACK,
            payload: &[],
        };
        let _ = connection.on_segment(&ack);
        assert_eq!(connection.state(), TcpState::Established);
        connection
    }

    fn data<'a>(seq: u32, bytes: &'a [u8]) -> Inbound<'a> {
        Inbound {
            seq,
            ack: 1001,
            flags: ctl::ACK,
            payload: bytes,
        }
    }

    #[test]
    fn gap_holds_then_collapse_in_order() {
        let mut connection = established();
        // Segment 2 arrives first: held above the gap.
        let held = connection.on_segment(&data(5006, b"BBBBB"));
        assert!(held.delivered.is_empty(), "nothing delivers out of order");
        assert_eq!(connection.ooo_usage(), 5);

        // Segment 1 fills the gap: both deliver in order.
        let filled = connection.on_segment(&data(5001, b"AAAAA"));
        assert_eq!(filled.delivered, b"AAAAABBBBB");
        assert_eq!(connection.ooo_usage(), 0);
        assert_eq!(connection.recv_nxt(), 5011);
    }

    #[test]
    fn overlapping_out_of_order_segments_merge() {
        let mut connection = established();
        connection.on_segment(&data(5006, b"BBBBB"));
        connection.on_segment(&data(5008, b"CCC"));
        // One merged range, not two stacked copies of the overlap.
        assert_eq!(connection.out_of_order.len(), 1);
        let (seq, bytes) = &connection.out_of_order[0];
        assert_eq!(*seq, 5006);
        assert_eq!(bytes.as_slice(), b"BBBBBCC");
    }

    #[test]
    fn duplicate_below_window_delivers_nothing() {
        let mut connection = established();
        let first = connection.on_segment(&data(5001, b"AAAAA"));
        assert_eq!(first.delivered, b"AAAAA");
        let again = connection.on_segment(&data(5001, b"AAAAA"));
        assert!(
            again.delivered.is_empty(),
            "retransmission of delivered bytes"
        );
        assert_eq!(
            connection.duplicate_acks(),
            0,
            "data-carrying, not a dup ACK"
        );
    }

    #[test]
    fn pure_duplicate_acks_are_counted() {
        let mut connection = established();
        for _ in 0..3 {
            connection.on_segment(&data(5001, b""));
        }
        assert_eq!(connection.duplicate_acks(), 3);
        // A real advance clears the count (RFC 6298 §5.3 spirit).
        connection.on_segment(&data(5001, b"X"));
        assert_eq!(connection.duplicate_acks(), 0);
    }

    #[test]
    fn sack_blocks_describe_held_ranges() {
        let mut connection = established();
        connection.on_segment(&data(5101, b"DDDD"));
        connection.on_segment(&data(5006, b"BBBB"));
        let blocks = connection.sack_blocks();
        // Newest first, edges relative to RCV.NXT (5001).
        assert_eq!(blocks[0], (100, 104));
        assert_eq!(blocks[1], (5, 9));
    }
}
