// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Packet construction: the write side of the wire crate.
//!
//! The parsers see packets that arrived; these builders produce the few
//! packets we send back unprompted. RST generation follows RFC 9293 §3.4:
//! whether the reset carries an ACK, and which sequence number it uses,
//! is decided by the offending segment, not by the caller. The ICMPv4
//! unreachable quotes the offending IP header plus eight octets of its
//! payload, which RFC 792 requires so the sender can match the error to
//! its socket.
//!
//! IPv6 envelopes arrive with the in-house stack, which is the first
//! consumer that can carry a full v6 flow table; nothing here blocks it.

use crate::checksum;
use crate::ipv4::Ipv4Header;
use crate::protocol::IpProtocol;
use crate::tcp::{TcpFlags, TcpHeader};
use std::net::{Ipv4Addr, SocketAddrV4};

/// The TTL stamped on generated packets; a host default, since these
/// packets never travel far.
const GENERATED_TTL: u8 = 64;

/// Build the RST for a refused flow from the offending segment, wrapped
/// in an IPv4 envelope.
///
/// The reset is addressed from `from` (our address on that flow) back to
/// the offending source, with the ports swapped. Per RFC 9293 §3.4:
/// an offending segment carrying an ACK yields `<SEQ=SEG.ACK><CTL=RST>`;
/// anything else yields `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`.
///
/// Returns `None` when `offending` is not a parseable TCP-over-IPv4
/// packet, since any reset built from guessed fields would be worse than
/// silence.
pub fn tcp_rst_v4(offending: &[u8], from: Ipv4Addr) -> Option<Vec<u8>> {
    let (ip, payload) = Ipv4Header::parse(offending).ok()?;
    if ip.protocol != IpProtocol::Tcp {
        return None;
    }
    let (tcp, seg_payload) = TcpHeader::parse(payload).ok()?;
    // SEG.LEN counts the payload plus one octet each for SYN and FIN,
    // which the sequence space consumed even though no bytes moved.
    let seg_len = seg_payload.len() as u32
        + u32::from(tcp.flags.contains(TcpFlags::SYN))
        + u32::from(tcp.flags.contains(TcpFlags::FIN));

    let (seq, ack, flags) = if tcp.flags.contains(TcpFlags::ACK) {
        (tcp.ack, 0, TcpFlags::RST)
    } else {
        (
            0,
            tcp.seq.wrapping_add(seg_len),
            TcpFlags::RST.union(TcpFlags::ACK),
        )
    };

    let segment = tcp_segment(
        tcp.dst_port,
        tcp.src_port,
        seq,
        ack,
        flags,
        0,
        &[],
        ip.src,
        from,
    );
    Some(ipv4_envelope(from, ip.src, IpProtocol::Tcp, &segment))
}

/// Build the RST that tears down an established flow we own, with the
/// sequence state of both directions at abort time.
///
/// Unlike a refusal reset, this one carries our own next sequence number
/// so the peer accepts it against the open connection: `<SEQ=SND.NXT>
/// <ACK=RCV.NXT><CTL=RST,ACK>`.
pub fn tcp_rst_teardown_v4(
    local: SocketAddrV4,
    remote: SocketAddrV4,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    let segment = tcp_segment(
        local.port(),
        remote.port(),
        seq,
        ack,
        TcpFlags::RST.union(TcpFlags::ACK),
        0,
        &[],
        *local.ip(),
        *remote.ip(),
    );
    ipv4_envelope(*local.ip(), *remote.ip(), IpProtocol::Tcp, &segment)
}

/// Build an ICMPv4 destination-unreachable error quoting `offending`.
///
/// `code` selects the reason; code 3 (port unreachable) is the one a
/// refused datagram flow produces. The message quotes the offending IP
/// header and the first eight octets of its payload, per RFC 792, which
/// is exactly what the sender needs to find the socket responsible.
pub fn icmpv4_unreachable_v4(from: Ipv4Addr, offending: &[u8], code: u8) -> Option<Vec<u8>> {
    let (ip, _) = Ipv4Header::parse(offending).ok()?;
    let quote_end = offending.len().min(ip.header_len + 8);
    let quote = &offending[..quote_end];

    // Type 3 (destination unreachable), code, checksum, then the quote.
    let mut msg = Vec::with_capacity(8 + quote.len());
    msg.extend_from_slice(&[3, code, 0, 0, 0, 0, 0, 0]);
    msg.extend_from_slice(quote);
    let sum = checksum::sum_words(&msg);
    msg[4..6].copy_from_slice(&(!checksum::fold(sum)).to_be_bytes());

    Some(ipv4_envelope(from, ip.src, IpProtocol::Icmp, &msg))
}

/// Serialize a TCP header over `payload`. The checksum covers the pseudo
/// header and the segment, so the addresses are needed here too.
#[allow(clippy::too_many_arguments)]
fn tcp_segment(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&src_port.to_be_bytes());
    seg.extend_from_slice(&dst_port.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(5 << 4); // data offset: no options
    seg.push(flags.bits());
    seg.extend_from_slice(&window.to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum, filled below
    seg.extend_from_slice(&[0, 0]); // urgent pointer
    seg.extend_from_slice(payload);

    let sum = checksum::pseudo_header_v4(src, dst, IpProtocol::Tcp, seg.len() as u32)
        + checksum::sum_words(&seg);
    seg[16..18].copy_from_slice(&(!checksum::fold(sum)).to_be_bytes());
    seg
}

/// Wrap a transport message in a minimal IPv4 envelope with a verified
/// header checksum.
fn ipv4_envelope(src: Ipv4Addr, dst: Ipv4Addr, protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let mut pkt = Vec::with_capacity(20 + payload.len());
    pkt.push(4 << 4 | 5); // version, IHL
    pkt.push(0); // DSCP/ECN
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0, 0]); // identification
    pkt.extend_from_slice(&[0x40, 0]); // don't fragment, offset zero
    pkt.push(GENERATED_TTL);
    pkt.push(protocol_to_byte(protocol));
    pkt.extend_from_slice(&[0, 0]); // header checksum, filled below
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    pkt.extend_from_slice(payload);

    let sum = checksum::sum_words(&pkt[..20]);
    pkt[10..12].copy_from_slice(&(!checksum::fold(sum)).to_be_bytes());
    pkt
}

fn protocol_to_byte(protocol: IpProtocol) -> u8 {
    match protocol {
        IpProtocol::Tcp => 6,
        IpProtocol::Udp => 17,
        IpProtocol::Icmp => 1,
        IpProtocol::Icmpv6 => 58,
        other => {
            if let IpProtocol::Other(v) = other {
                v
            } else {
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::verify_transport_v4;

    fn syn_from_client(seq: u32) -> Vec<u8> {
        let segment = tcp_segment(
            45678,
            443,
            seq,
            0,
            TcpFlags::SYN,
            65535,
            &[],
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        ipv4_envelope(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 1),
            IpProtocol::Tcp,
            &segment,
        )
    }

    fn parse_rst(pkt: &[u8]) -> (Ipv4Header, TcpHeader) {
        let (ip, payload) = Ipv4Header::parse(pkt).expect("parse IPv4");
        let (tcp, _) = TcpHeader::parse(payload).expect("parse TCP");
        (ip, tcp)
    }

    #[test]
    fn rst_for_syn_carries_seq_zero_and_ack_isn_plus_one() {
        let offending = syn_from_client(1000);
        let rst = tcp_rst_v4(&offending, Ipv4Addr::new(10, 0, 0, 1)).expect("build RST");

        let (ip, tcp) = parse_rst(&rst);
        assert_eq!(ip.src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip.dst, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(tcp.src_port, 443);
        assert_eq!(tcp.dst_port, 45678);
        // <SEQ=0><ACK=ISN+1><CTL=RST,ACK> per RFC 9293 §3.4.
        assert_eq!(tcp.seq, 0);
        assert_eq!(tcp.ack, 1001);
        assert!(tcp.flags.contains(TcpFlags::RST));
        assert!(tcp.flags.contains(TcpFlags::ACK));
    }

    #[test]
    fn rst_for_acked_segment_takes_seq_from_seg_ack() {
        // A data segment that carries an ACK: the reset answers with
        // <SEQ=SEG.ACK><CTL=RST> and no ACK flag of its own.
        let segment = tcp_segment(
            45678,
            443,
            2000,
            3001,
            TcpFlags::ACK.union(TcpFlags::PSH),
            65535,
            &[7; 100],
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        let offending = ipv4_envelope(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(10, 0, 0, 1),
            IpProtocol::Tcp,
            &segment,
        );

        let rst = tcp_rst_v4(&offending, Ipv4Addr::new(10, 0, 0, 1)).expect("build RST");
        let (_, tcp) = parse_rst(&rst);
        assert_eq!(tcp.seq, 3001);
        assert_eq!(tcp.ack, 0);
        assert!(tcp.flags.contains(TcpFlags::RST));
        assert!(!tcp.flags.contains(TcpFlags::ACK));
    }

    #[test]
    fn teardown_rst_carries_both_directions_state() {
        let local = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);
        let remote = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 45678);
        let pkt = tcp_rst_teardown_v4(local, remote, 5001, 8002);

        let (ip, tcp) = parse_rst(&pkt);
        assert_eq!(ip.src, *local.ip());
        assert_eq!(ip.dst, *remote.ip());
        assert_eq!(tcp.seq, 5001);
        assert_eq!(tcp.ack, 8002);
        assert!(tcp.flags.contains(TcpFlags::RST));
        assert!(tcp.flags.contains(TcpFlags::ACK));
    }

    #[test]
    fn generated_rst_checksums_verify() {
        let offending = syn_from_client(1000);
        let rst = tcp_rst_v4(&offending, Ipv4Addr::new(10, 0, 0, 1)).expect("build RST");

        let (ip, payload) = Ipv4Header::parse(&rst).expect("parse IPv4");
        // The header checksum folds back to zero.
        assert_eq!(
            checksum::fold(checksum::sum_words(&rst[..ip.header_len])),
            0xffff
        );
        // The transport checksum verifies through the pseudo header.
        assert!(verify_transport_v4(
            ip.src,
            ip.dst,
            IpProtocol::Tcp,
            payload
        ));
    }

    #[test]
    fn unreachable_quotes_offending_header_and_eight_octets() {
        let offending = syn_from_client(1000);
        let err = icmpv4_unreachable_v4(Ipv4Addr::new(10, 0, 0, 1), &offending, 3)
            .expect("build unreachable");

        let (ip, payload) = Ipv4Header::parse(&err).expect("parse IPv4");
        assert_eq!(ip.protocol, IpProtocol::Icmp);
        assert_eq!(payload[0], 3); // destination unreachable
        assert_eq!(payload[1], 3); // port unreachable
        // The quote is the offending header plus eight octets.
        assert_eq!(payload.len(), 8 + 20 + 8);
        assert_eq!(&payload[8..8 + 20], &offending[..20]);
        assert_eq!(&payload[28..], &offending[20..28]);
    }

    #[test]
    fn garbage_offender_yields_no_reset() {
        assert!(tcp_rst_v4(&[0u8; 4], Ipv4Addr::LOCALHOST).is_none());
        assert!(icmpv4_unreachable_v4(Ipv4Addr::LOCALHOST, &[0u8; 4], 3).is_none());
    }
}
