// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The TCP flows ipstack holds open, as the bridge sees them on the
//! wire, and the resets that end them when the stack stops.
//!
//! sing-tun's gVisor stack aborts every endpoint it still holds on close
//! and closes the tun after (stack_gvisor.go:131-135); a connected
//! endpoint's abort sends `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=RST,ACK>`
//! (gVisor connect.go:1069-1088). ipstack 1.0 has no abort: a dropped
//! stream ends its task without a segment, and its sequence state is
//! private. Everything ipstack emits crosses the bridge, though, so the
//! cursors a reset needs are readable there: SND.NXT is the end of the
//! furthest segment ipstack sent, RCV.NXT the last acknowledgment it
//! sent.
//!
//! Like the native stack, only flows the client has acknowledged into
//! ESTABLISHED are reset; a flow still in SYN-RECEIVED goes silent, as
//! gVisor's `connected()` leaves it. A flow leaves the table when either
//! side resets it or when its stream is dropped — after that ipstack
//! sends nothing more for it, so there is no cursor to keep.
//!
//! Addresses here are ipstack's view: the bridge observes inbound frames
//! after the DNS rewrite and outbound frames before it is undone, and the
//! resets travel the same writer, which undoes it on them too.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use vfawn_wire::{IpProtocol, Ipv4Header, Ipv6Header, TcpFlags, TcpHeader, V6Payload};

/// One TCP segment read off an IP frame.
pub(crate) struct Segment<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub tcp: TcpHeader,
    pub payload: &'a [u8],
}

/// Read the TCP segment an IPv4 or IPv6 frame carries. Non-TCP frames,
/// later fragments and anything unparseable answer `None`.
pub(crate) fn tcp_segment(packet: &[u8]) -> Option<Segment<'_>> {
    let (src, dst, bytes) = match packet.first()? >> 4 {
        4 => {
            let (ip, payload) = Ipv4Header::parse(packet).ok()?;
            if ip.protocol != IpProtocol::Tcp || ip.fragment_offset != 0 {
                return None;
            }
            (IpAddr::V4(ip.src), IpAddr::V4(ip.dst), payload)
        }
        6 => {
            let (ip, rest) = Ipv6Header::parse(packet).ok()?;
            let payload = V6Payload::walk(ip.next_header, rest).ok()?;
            if payload.protocol != IpProtocol::Tcp
                || payload
                    .fragment
                    .is_some_and(|fragment| fragment.offset != 0)
            {
                return None;
            }
            (IpAddr::V6(ip.src), IpAddr::V6(ip.dst), payload.bytes)
        }
        _ => return None,
    };
    let (tcp, payload) = TcpHeader::parse(bytes).ok()?;
    Some(Segment {
        src: SocketAddr::new(src, tcp.src_port),
        dst: SocketAddr::new(dst, tcp.dst_port),
        tcp,
        payload,
    })
}

/// A flow's identity: the client's address, then the address it reached.
type Key = (SocketAddr, SocketAddr);

/// What a reset for one flow needs.
struct Cursor {
    snd_nxt: u32,
    rcv_nxt: u32,
    established: bool,
}

#[derive(Default)]
struct State {
    flows: HashMap<Key, Cursor>,
    sealed: bool,
}

/// The live flows behind one ipstack instance.
#[derive(Default)]
pub struct LiveFlows {
    state: Mutex<State>,
}

/// `a` lies after `b` in sequence space (RFC 9293 §3.4 arithmetic).
fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Move `cursor` forward to `to`; never back.
fn advance(cursor: &mut u32, to: u32) {
    if after(to, *cursor) {
        *cursor = to;
    }
}

impl LiveFlows {
    /// A frame from the client toward ipstack. Its ACK completes the
    /// handshake; its RST ends the flow.
    pub fn inbound(&self, packet: &[u8]) {
        let Some(segment) = tcp_segment(packet) else {
            return;
        };
        let flags = segment.tcp.flags;
        let key = (segment.src, segment.dst);
        let mut state = self.lock();
        if flags.contains(TcpFlags::RST) {
            state.flows.remove(&key);
        } else if flags.contains(TcpFlags::ACK)
            && !flags.contains(TcpFlags::SYN)
            && let Some(cursor) = state.flows.get_mut(&key)
        {
            cursor.established = true;
        }
    }

    /// A frame from ipstack toward the client: account for it, then hand
    /// it on through `send` under the same lock, so nothing ipstack emits
    /// passes after [`LiveFlows::seal`] took its cursors. `None` once
    /// sealed: the frame is not sent.
    pub fn outbound<T>(&self, packet: &[u8], send: impl FnOnce() -> T) -> Option<T> {
        let mut state = self.lock();
        if state.sealed {
            return None;
        }
        if let Some(segment) = tcp_segment(packet) {
            account(&mut state.flows, &segment);
        }
        Some(send())
    }

    /// The flow's stream is gone: ipstack sends nothing more for it.
    pub fn forget(&self, client: SocketAddr, server: SocketAddr) {
        self.lock().flows.remove(&(client, server));
    }

    /// A guard that forgets the flow when dropped, to ride along with
    /// the flow's stream.
    pub fn hold(self: &Arc<Self>, client: SocketAddr, server: SocketAddr) -> FlowHold {
        FlowHold {
            flows: Arc::clone(self),
            client,
            server,
        }
    }

    /// Refuse every later outbound frame and answer one reset for each
    /// established flow, from the cursors the wire last showed.
    pub fn seal(&self) -> Vec<Vec<u8>> {
        let mut state = self.lock();
        state.sealed = true;
        std::mem::take(&mut state.flows)
            .into_iter()
            .filter(|(_, cursor)| cursor.established)
            .filter_map(|((client, server), cursor)| {
                teardown(server, client, cursor.snd_nxt, cursor.rcv_nxt)
            })
            .collect()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Fold one ipstack segment into its flow's cursors. A SYN-ACK opens the
/// flow; a RST ends it; every segment advances SND.NXT to its end and
/// RCV.NXT to its acknowledgment. Retransmissions end before SND.NXT and
/// leave it alone. Data ipstack lets out ahead of its own SYN-ACK sits
/// before the ISN the SYN-ACK announces: the client discards it, and the
/// SYN-ACK's end is the cursor the client holds.
fn account(flows: &mut HashMap<Key, Cursor>, segment: &Segment<'_>) {
    let flags = segment.tcp.flags;
    let key = (segment.dst, segment.src);
    if flags.contains(TcpFlags::RST) {
        flows.remove(&key);
        return;
    }
    let end = segment
        .tcp
        .seq
        .wrapping_add(segment.payload.len() as u32)
        .wrapping_add(u32::from(flags.contains(TcpFlags::SYN)))
        .wrapping_add(u32::from(flags.contains(TcpFlags::FIN)));
    if flags.contains(TcpFlags::SYN) && flags.contains(TcpFlags::ACK) {
        flows.entry(key).or_insert(Cursor {
            snd_nxt: end,
            rcv_nxt: segment.tcp.ack,
            established: false,
        });
        return;
    }
    let Some(cursor) = flows.get_mut(&key) else {
        return;
    };
    advance(&mut cursor.snd_nxt, end);
    if flags.contains(TcpFlags::ACK) {
        advance(&mut cursor.rcv_nxt, segment.tcp.ack);
    }
}

/// `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=RST,ACK>` from `local` to `remote`.
fn teardown(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32) -> Option<Vec<u8>> {
    match (local, remote) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            Some(vfawn_wire::tcp_rst_teardown_v4(local, remote, seq, ack))
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            Some(vfawn_wire::tcp_rst_teardown_v6(local, remote, seq, ack))
        }
        _ => None,
    }
}

/// Forgets its flow when dropped; see [`LiveFlows::hold`].
pub struct FlowHold {
    flows: Arc<LiveFlows>,
    client: SocketAddr,
    server: SocketAddr,
}

impl Drop for FlowHold {
    fn drop(&mut self) {
        self.flows.forget(self.client, self.server);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 18, 0, 1), 50000);
    const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 18, 0, 2), 80);

    /// A TCP/IPv4 frame with `payload`, built by flipping the flags of a
    /// teardown frame (the builders carry no payload of their own).
    fn frame(
        from: SocketAddrV4,
        to: SocketAddrV4,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vfawn_wire::tcp_rst_teardown_v4(from, to, seq, ack);
        packet[33] = flags.bits();
        packet.extend_from_slice(payload);
        let total = packet.len() as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet
    }

    fn syn_ack(flows: &LiveFlows) {
        let packet = frame(
            SERVER,
            CLIENT,
            1000,
            501,
            TcpFlags::SYN.union(TcpFlags::ACK),
            &[],
        );
        flows.outbound(&packet, || ()).unwrap();
    }

    fn client_ack(flows: &LiveFlows) {
        flows.inbound(&frame(CLIENT, SERVER, 501, 1001, TcpFlags::ACK, &[]));
    }

    fn reset_cursors(packet: &[u8]) -> (SocketAddr, SocketAddr, u32, u32, TcpFlags) {
        let segment = tcp_segment(packet).unwrap();
        (
            segment.src,
            segment.dst,
            segment.tcp.seq,
            segment.tcp.ack,
            segment.tcp.flags,
        )
    }

    #[test]
    fn an_established_flow_is_reset_with_both_cursors() {
        let flows = LiveFlows::default();
        syn_ack(&flows);
        client_ack(&flows);
        // ipstack sends three bytes and acknowledges five from the client.
        let data = frame(SERVER, CLIENT, 1001, 506, TcpFlags::ACK, b"abc");
        flows.outbound(&data, || ()).unwrap();
        // A retransmission of the first byte moves nothing back.
        let again = frame(SERVER, CLIENT, 1001, 506, TcpFlags::ACK, b"a");
        flows.outbound(&again, || ()).unwrap();

        let resets = flows.seal();
        assert_eq!(resets.len(), 1);
        assert_eq!(
            reset_cursors(&resets[0]),
            (
                SERVER.into(),
                CLIENT.into(),
                1004,
                506,
                TcpFlags::RST.union(TcpFlags::ACK)
            )
        );
    }

    #[test]
    fn a_fin_takes_its_octet_of_sequence_space() {
        let flows = LiveFlows::default();
        syn_ack(&flows);
        client_ack(&flows);
        let fin = frame(
            SERVER,
            CLIENT,
            1001,
            501,
            TcpFlags::FIN.union(TcpFlags::ACK),
            &[],
        );
        flows.outbound(&fin, || ()).unwrap();
        assert_eq!(reset_cursors(&flows.seal()[0]).2, 1002);
    }

    /// ipstack can let a stream's first write out ahead of its SYN-ACK,
    /// numbered before the ISN the SYN-ACK then announces (seen in the
    /// wire log of a loaded run). The client discards it; the reset
    /// follows the SYN-ACK.
    #[test]
    fn data_ahead_of_the_syn_ack_is_not_counted() {
        let flows = LiveFlows::default();
        let early = frame(SERVER, CLIENT, 995, 500, TcpFlags::ACK, b"hello");
        flows.outbound(&early, || ()).unwrap();
        syn_ack(&flows);
        client_ack(&flows);
        let (_, _, seq, ack, _) = reset_cursors(&flows.seal()[0]);
        assert_eq!((seq, ack), (1001, 501));
    }

    #[test]
    fn a_half_open_flow_is_not_reset() {
        let flows = LiveFlows::default();
        syn_ack(&flows);
        assert!(flows.seal().is_empty());
    }

    #[test]
    fn a_reset_either_way_or_a_dropped_stream_ends_the_flow() {
        let from_client = LiveFlows::default();
        syn_ack(&from_client);
        client_ack(&from_client);
        from_client.inbound(&frame(CLIENT, SERVER, 501, 0, TcpFlags::RST, &[]));
        assert!(from_client.seal().is_empty());

        let from_stack = LiveFlows::default();
        syn_ack(&from_stack);
        client_ack(&from_stack);
        let reset = frame(
            SERVER,
            CLIENT,
            1001,
            501,
            TcpFlags::RST.union(TcpFlags::ACK),
            &[],
        );
        from_stack.outbound(&reset, || ()).unwrap();
        assert!(from_stack.seal().is_empty());

        let dropped = Arc::new(LiveFlows::default());
        syn_ack(&dropped);
        client_ack(&dropped);
        drop(dropped.hold(CLIENT.into(), SERVER.into()));
        assert!(dropped.seal().is_empty());
    }

    #[test]
    fn nothing_passes_once_sealed() {
        let flows = LiveFlows::default();
        flows.seal();
        let data = frame(SERVER, CLIENT, 1, 1, TcpFlags::ACK, b"x");
        assert!(flows.outbound(&data, || ()).is_none());
    }
}
