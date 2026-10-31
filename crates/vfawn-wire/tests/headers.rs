// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Header parser test vectors, built byte by byte so the tests do not
//! depend on any packet-crafting library.

use std::net::{Ipv4Addr, Ipv6Addr};
use vfawn_wire::Icmpv4Header;
use vfawn_wire::ParseError;
use vfawn_wire::checksum;
use vfawn_wire::flow::{flow_key, fragment_info};
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::ipv6::{Ipv6Header, V6Payload};
use vfawn_wire::protocol::IpProtocol;
use vfawn_wire::tcp::TcpFlags;
use vfawn_wire::tcp::TcpHeader;
use vfawn_wire::udp::UdpHeader;

const V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const V4_DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const V6_SRC: Ipv6Addr = Ipv6Addr::LOCALHOST;
const V6_DST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

fn push16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn push32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// An IPv4 header with caller-selected fragment control and an options
/// word count; payload follows.
fn v4_packet(protocol: u8, options_words: u8, frag: (u16, u16, bool), payload: &[u8]) -> Vec<u8> {
    let header_len = 20 + options_words as usize * 4;
    let mut buf = Vec::with_capacity(header_len + payload.len());
    buf.push(0x45 + options_words);
    buf.push(0);
    push16(&mut buf, (header_len + payload.len()) as u16);
    push16(&mut buf, frag.0);
    let mut flags = frag.1 & 0x1fff;
    if frag.2 {
        flags |= 0x2000;
    }
    push16(&mut buf, flags);
    buf.push(64);
    buf.push(protocol);
    push16(&mut buf, 0);
    buf.extend_from_slice(&V4_SRC.octets());
    buf.extend_from_slice(&V4_DST.octets());
    buf.resize(header_len, 0);
    buf.extend_from_slice(payload);
    // Store the checksum computed over the zero-field header; the stored
    // value is exactly what makes the full header fold to all ones.
    let stored = checksum::checksum(&buf[..header_len]);
    buf[10] = (stored >> 8) as u8;
    buf[11] = stored as u8;
    buf
}

/// A UDP segment with a correct checksum.
fn udp_segment(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut seg = Vec::with_capacity(8 + payload.len());
    push16(&mut seg, sport);
    push16(&mut seg, dport);
    push16(&mut seg, (8 + payload.len()) as u16);
    push16(&mut seg, 0);
    seg.extend_from_slice(payload);
    let sum = checksum::fold(
        checksum::pseudo_header_v4(src, dst, IpProtocol::Udp, seg.len() as u32)
            + checksum::sum_words(&seg),
    );
    let written = !sum;
    seg[6] = (written >> 8) as u8;
    seg[7] = written as u8;
    seg
}

fn tcp_segment(flags: TcpFlags, options_words: u8) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + options_words as usize * 4);
    push16(&mut seg, 1234);
    push16(&mut seg, 443);
    push32(&mut seg, 1000);
    push32(&mut seg, 2000);
    seg.push(0x50 + options_words * 0x10);
    seg.push(flags.bits());
    push16(&mut seg, 0x2000);
    push16(&mut seg, 0);
    push16(&mut seg, 0);
    seg.resize(20 + options_words as usize * 4, 0);
    seg
}

/// An IPv6 fixed header; the caller supplies what follows.
fn v6_packet(next: u8, rest: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40 + rest.len());
    buf.extend_from_slice(&[0x60, 0, 0, 0]);
    push16(&mut buf, rest.len() as u16);
    buf.push(next);
    buf.push(64);
    buf.extend_from_slice(&V6_SRC.octets());
    buf.extend_from_slice(&V6_DST.octets());
    buf.extend_from_slice(rest);
    buf
}

/// An extension header of the given type whose declared length covers
/// `body` bytes after the first eight.
fn ext_header(next: u8, units: u8, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + body.len());
    buf.push(next);
    buf.push(units);
    buf.extend_from_slice(&[0; 6]);
    buf.extend_from_slice(body);
    buf
}

fn fragment_header_v6(next: u8, offset: u16, more: bool, id: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    buf.push(next);
    buf.push(0);
    let field = (offset << 3) | more as u16;
    push16(&mut buf, field);
    push32(&mut buf, id);
    buf
}

#[test]
fn ipv4_minimal_udp_packet_parses_with_fields() {
    let payload = udp_segment(V4_SRC, V4_DST, 5353, 53, b"abcd");
    let packet = v4_packet(17, 0, (7, 0, false), &payload);
    let (header, rest) = Ipv4Header::parse(&packet).unwrap();
    assert_eq!(header.src, V4_SRC);
    assert_eq!(header.dst, V4_DST);
    assert_eq!(header.protocol, IpProtocol::Udp);
    assert_eq!(header.total_len as usize, 20 + payload.len());
    assert_eq!(header.identification, 7);
    assert!(!header.more_fragments);
    assert_eq!(header.fragment_offset, 0);
    assert_eq!(header.header_len, 20);
    assert_eq!(rest.len(), payload.len());
}

#[test]
fn ipv4_options_extend_the_header() {
    let payload = udp_segment(V4_SRC, V4_DST, 1000, 2000, b"x");
    let packet = v4_packet(17, 2, (0, 0, false), &payload);
    let (header, rest) = Ipv4Header::parse(&packet).unwrap();
    assert_eq!(header.header_len, 28);
    assert_eq!(rest.len(), payload.len());
}

#[test]
fn ipv4_trailing_padding_is_trimmed_to_total_length() {
    let payload = udp_segment(V4_SRC, V4_DST, 1, 2, b"zz");
    let mut packet = v4_packet(17, 0, (0, 0, false), &payload);
    packet.extend_from_slice(&[0u8; 6]);
    let (_, rest) = Ipv4Header::parse(&packet).unwrap();
    assert_eq!(rest.len(), payload.len());
}

#[test]
fn ipv4_rejects_short_buffers() {
    assert_eq!(
        Ipv4Header::parse(&[0x45, 0]).unwrap_err(),
        ParseError::Truncated
    );
}

#[test]
fn ipv4_rejects_wrong_version() {
    let mut packet = v4_packet(
        17,
        0,
        (0, 0, false),
        &udp_segment(V4_SRC, V4_DST, 1, 2, b"q"),
    );
    packet[0] = 0x55;
    assert_eq!(
        Ipv4Header::parse(&packet).unwrap_err(),
        ParseError::Malformed("not IPv4")
    );
}

#[test]
fn ipv4_rejects_ihl_below_minimum() {
    let mut packet = v4_packet(
        17,
        0,
        (0, 0, false),
        &udp_segment(V4_SRC, V4_DST, 1, 2, b"q"),
    );
    packet[0] = 0x44;
    assert_eq!(
        Ipv4Header::parse(&packet).unwrap_err(),
        ParseError::Malformed("IHL below minimum")
    );
}

#[test]
fn ipv4_rejects_total_length_below_header() {
    let mut packet = v4_packet(
        17,
        0,
        (0, 0, false),
        &udp_segment(V4_SRC, V4_DST, 1, 2, b"q"),
    );
    packet[2] = 0;
    packet[3] = 4;
    assert_eq!(
        Ipv4Header::parse(&packet).unwrap_err(),
        ParseError::Malformed("total length below header length")
    );
}

#[test]
fn ipv4_header_checksum_verifies_and_fails() {
    let payload = udp_segment(V4_SRC, V4_DST, 1, 2, b"q");
    let packet = v4_packet(17, 0, (0, 0, false), &payload);
    assert!(Ipv4Header::verify_checksum(&packet));
    let mut broken = packet.clone();
    broken[8] ^= 0xff;
    assert!(!Ipv4Header::verify_checksum(&broken));
}

#[test]
fn tcp_header_parses_with_flags_and_options() {
    let seg = tcp_segment(TcpFlags::SYN.union(TcpFlags::ACK), 1);
    let (header, rest) = TcpHeader::parse(&seg).unwrap();
    assert_eq!(header.src_port, 1234);
    assert_eq!(header.dst_port, 443);
    assert_eq!(header.seq, 1000);
    assert_eq!(header.ack, 2000);
    assert!(header.flags.contains(TcpFlags::SYN));
    assert!(!header.flags.is_syn());
    assert!(header.flags.is_pure_ack() || header.flags.contains(TcpFlags::ACK));
    assert_eq!(header.header_len, 24);
    assert!(rest.is_empty());
}

#[test]
fn tcp_syn_detection() {
    let syn = tcp_segment(TcpFlags::SYN, 0);
    let (_, _) = TcpHeader::parse(&syn).unwrap();
    assert!(TcpFlags::from_bits(0x02).is_syn());
    assert!(!TcpFlags::from_bits(0x12).is_syn());
    assert!(TcpFlags::from_bits(0x10).is_pure_ack());
    assert!(!TcpFlags::from_bits(0x02).is_pure_ack());
}

#[test]
fn tcp_rejects_truncated_and_bad_offset() {
    assert_eq!(
        TcpHeader::parse(&[0u8; 19]).unwrap_err(),
        ParseError::Truncated
    );
    let mut seg = tcp_segment(TcpFlags::ACK, 0);
    seg[12] = 0x40;
    assert_eq!(
        TcpHeader::parse(&seg).unwrap_err(),
        ParseError::Malformed("data offset below minimum")
    );
    let mut seg = tcp_segment(TcpFlags::ACK, 0);
    seg[12] = 0x60;
    assert_eq!(TcpHeader::parse(&seg).unwrap_err(), ParseError::Truncated);
}

#[test]
fn udp_header_parses_and_bounds_payload() {
    let mut seg = Vec::new();
    push16(&mut seg, 50000);
    push16(&mut seg, 53);
    push16(&mut seg, 15);
    push16(&mut seg, 0);
    seg.extend_from_slice(b"payload");
    let (header, rest) = UdpHeader::parse(&seg).unwrap();
    assert_eq!(header.src_port, 50000);
    assert_eq!(header.dst_port, 53);
    assert_eq!(header.length, 15);
    assert_eq!(rest, b"payload");
}

#[test]
fn udp_rejects_truncated_and_short_length_field() {
    assert_eq!(
        UdpHeader::parse(&[0u8; 7]).unwrap_err(),
        ParseError::Truncated
    );
    let mut seg = vec![0u8; 8];
    seg[4] = 0;
    seg[5] = 3;
    assert_eq!(
        UdpHeader::parse(&seg).unwrap_err(),
        ParseError::Malformed("length below header size")
    );
}

#[test]
fn icmpv4_parses_echo_request() {
    let mut msg = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 1];
    msg.extend_from_slice(b"ping");
    let (header, rest) = Icmpv4Header::parse(&msg).unwrap();
    assert_eq!(header.kind, vfawn_wire::icmpv4::ECHO_REQUEST);
    assert_eq!(header.code, 0);
    assert_eq!(rest, &[0x12, 0x34, 0, 1, b'p', b'i', b'n', b'g']);
    assert_eq!(
        Icmpv4Header::parse(&[1, 2, 3]).unwrap_err(),
        ParseError::Truncated
    );
}

#[test]
fn ipv6_fixed_header_parses() {
    let packet = v6_packet(6, &tcp_segment(TcpFlags::SYN, 0));
    let (header, rest) = Ipv6Header::parse(&packet).unwrap();
    assert_eq!(header.src, V6_SRC);
    assert_eq!(header.dst, V6_DST);
    assert_eq!(header.next_header, IpProtocol::Tcp);
    assert_eq!(header.payload_len as usize, rest.len());
    assert_eq!(header.hop_limit, 64);
}

#[test]
fn ipv6_rejects_truncated_and_wrong_version() {
    assert_eq!(
        Ipv6Header::parse(&[0x60u8; 39]).unwrap_err(),
        ParseError::Truncated
    );
    let mut packet = v6_packet(6, &[]);
    packet[0] = 0x40;
    assert_eq!(
        Ipv6Header::parse(&packet).unwrap_err(),
        ParseError::Malformed("not IPv6")
    );
}

#[test]
fn ipv6_walk_skips_hop_by_hop_options() {
    let tcp = tcp_segment(TcpFlags::SYN, 0);
    let mut rest = ext_header(6, 0, &[]);
    rest.extend_from_slice(&tcp);
    let packet = v6_packet(0, &rest);
    let (header, tail) = Ipv6Header::parse(&packet).unwrap();
    let payload = V6Payload::walk(header.next_header, tail).unwrap();
    assert_eq!(payload.protocol, IpProtocol::Tcp);
    assert!(payload.fragment.is_none());
    let (tcp_header, _) = TcpHeader::parse(payload.bytes).unwrap();
    assert_eq!(tcp_header.src_port, 1234);
}

#[test]
fn ipv6_walk_skips_multi_unit_extensions() {
    let udp = udp_segment(V4_SRC, V4_DST, 111, 222, b"hi");
    let mut rest = ext_header(43, 1, &[0u8; 8]);
    let dest = ext_header(17, 0, &[]);
    rest.extend_from_slice(&dest);
    rest.extend_from_slice(&udp);
    let packet = v6_packet(43, &rest);
    let (header, tail) = Ipv6Header::parse(&packet).unwrap();
    let payload = V6Payload::walk(header.next_header, tail).unwrap();
    assert_eq!(payload.protocol, IpProtocol::Udp);
    let (udp_header, _) = UdpHeader::parse(payload.bytes).unwrap();
    assert_eq!(udp_header.src_port, 111);
}

#[test]
fn ipv6_walk_handles_authentication_header_units() {
    // AH length counts in 4-octet units, so a field of 1 means 12 bytes.
    let mut ah = ext_header(6, 1, &[0u8; 4]);
    ah[1] = 1;
    let tcp = tcp_segment(TcpFlags::ACK, 0);
    let mut rest = ah;
    rest.extend_from_slice(&tcp);
    let packet = v6_packet(51, &rest);
    let (header, tail) = Ipv6Header::parse(&packet).unwrap();
    let payload = V6Payload::walk(header.next_header, tail).unwrap();
    assert_eq!(payload.protocol, IpProtocol::Tcp);
}

#[test]
fn ipv6_first_fragment_still_exposes_the_transport_header() {
    let tcp = tcp_segment(TcpFlags::SYN, 0);
    let mut rest = fragment_header_v6(6, 0, true, 0xfeedface);
    rest.extend_from_slice(&tcp);
    let packet = v6_packet(44, &rest);
    let (header, tail) = Ipv6Header::parse(&packet).unwrap();
    let payload = V6Payload::walk(header.next_header, tail).unwrap();
    let fragment = payload.fragment.unwrap();
    assert_eq!(fragment.identification, 0xfeedface);
    assert_eq!(fragment.offset, 0);
    assert!(fragment.more);
    assert_eq!(payload.protocol, IpProtocol::Tcp);
    assert!(TcpHeader::parse(payload.bytes).is_ok());
}

#[test]
fn ipv6_later_fragment_has_no_transport_header() {
    let rest = fragment_header_v6(6, 5, true, 42);
    let packet = v6_packet(44, &rest);
    let (header, tail) = Ipv6Header::parse(&packet).unwrap();
    let payload = V6Payload::walk(header.next_header, tail).unwrap();
    assert_eq!(payload.fragment.unwrap().offset, 5);
    assert!(payload.bytes.is_empty());
}

#[test]
fn ipv6_walk_rejects_truncated_extensions() {
    let rest = &[0u8; 4];
    let packet = v6_packet(0, rest);
    let (header, tail) = Ipv6Header::parse(&packet).unwrap();
    assert_eq!(
        V6Payload::walk(header.next_header, tail).unwrap_err(),
        ParseError::Truncated
    );
}

#[test]
fn ipv6_no_next_header_terminates() {
    let packet = v6_packet(59, &[]);
    let (header, tail) = Ipv6Header::parse(&packet).unwrap();
    let payload = V6Payload::walk(header.next_header, tail).unwrap();
    assert_eq!(payload.protocol, IpProtocol::NoNextHeader);
}

#[test]
fn checksum_matches_the_rfc1071_example() {
    // The classic worked example: the data sums to 0xddf2.
    let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    let sum = checksum::sum_words(&data);
    assert_eq!(checksum::fold(sum), 0xddf2);
    assert_eq!(checksum::checksum(&data), !0xddf2);
}

#[test]
fn checksum_handles_odd_and_even_lengths_identically_when_padded() {
    let even = [0x11u8, 0x22, 0x33, 0x44];
    let padded = [0x11u8, 0x22, 0x33, 0x44, 0x00];
    assert_eq!(checksum::checksum(&even), checksum::checksum(&padded));
}

#[test]
fn transport_checksum_verification_round_trips() {
    let src = Ipv4Addr::new(1, 2, 3, 4);
    let dst = Ipv4Addr::new(5, 6, 7, 8);
    let seg = udp_segment(src, dst, 999, 53, b"dns-query");
    assert!(checksum::verify_transport_v4(
        src,
        dst,
        IpProtocol::Udp,
        &seg
    ));
    let mut broken = seg.clone();
    broken[0] ^= 1;
    assert!(!checksum::verify_transport_v4(
        src,
        dst,
        IpProtocol::Udp,
        &broken
    ));
}

#[test]
fn v6_transport_checksum_verification_round_trips() {
    let tcp = tcp_segment(TcpFlags::SYN, 0);
    let mut seg = tcp.clone();
    let _claimed = {
        let sum = checksum::fold(
            checksum::pseudo_header_v6(V6_SRC, V6_DST, IpProtocol::Tcp, seg.len() as u32)
                + checksum::sum_words(&seg),
        );
        let written = !sum;
        seg[16] = (written >> 8) as u8;
        seg[17] = written as u8;
        written
    };
    assert!(checksum::verify_transport_v6(
        V6_SRC,
        V6_DST,
        IpProtocol::Tcp,
        &seg
    ));
}

#[test]
fn flow_key_extracts_v4_tcp_and_udp() {
    let udp = udp_segment(V4_SRC, V4_DST, 50000, 53, b"d");
    let packet = v4_packet(17, 0, (0, 0, false), &udp);
    let key = flow_key(&packet).unwrap();
    assert_eq!(key.src_port, 50000);
    assert_eq!(key.dst_port, 53);
    assert_eq!(key.protocol, IpProtocol::Udp);

    let tcp = tcp_segment(TcpFlags::SYN, 0);
    let packet = v4_packet(6, 0, (0, 0, false), &tcp);
    let key = flow_key(&packet).unwrap();
    assert_eq!(key.protocol, IpProtocol::Tcp);
    assert_eq!(key.src_port, 1234);
}

#[test]
fn flow_key_extracts_v6_through_extension_chain() {
    let udp = udp_segment(V4_SRC, V4_DST, 700, 800, b"");
    let mut rest = ext_header(17, 0, &[]);
    rest.extend_from_slice(&udp);
    let packet = v6_packet(0, &rest);
    let key = flow_key(&packet).unwrap();
    assert_eq!(key.protocol, IpProtocol::Udp);
    assert_eq!(key.src_port, 700);
    assert_eq!(key.dst_port, 800);
}

#[test]
fn flow_key_returns_none_for_non_transport() {
    let mut icmp = vec![8u8, 0, 0, 0, 1, 2, 3, 4];
    icmp.extend_from_slice(b"payload");
    let packet = v4_packet(1, 0, (0, 0, false), &icmp);
    assert!(flow_key(&packet).is_none());
    assert!(flow_key(&[]).is_none());
    assert!(flow_key(&[0x70, 0, 0, 0, 0]).is_none());
}

#[test]
fn flow_key_returns_none_for_later_fragments() {
    let udp = udp_segment(V4_SRC, V4_DST, 1, 2, b"abcdef");
    let packet = v4_packet(17, 0, (99, 1, true), &udp);
    assert!(flow_key(&packet).is_none());
    assert_eq!(fragment_info(&packet).unwrap().identification, 99);

    let rest = fragment_header_v6(17, 3, true, 7);
    let packet = v6_packet(44, &rest);
    assert!(flow_key(&packet).is_none());
    let frag = fragment_info(&packet).unwrap();
    assert_eq!(frag.identification, 7);
}

#[test]
fn first_fragments_keep_their_flow_key() {
    let udp = udp_segment(V4_SRC, V4_DST, 1, 2, b"abcdef");
    let packet = v4_packet(17, 0, (5, 0, true), &udp);
    let key = flow_key(&packet).unwrap();
    assert_eq!(key.src_port, 1);
    assert_eq!(fragment_info(&packet).unwrap().identification, 5);
}

#[test]
fn unfragmented_packets_have_no_fragment_identity() {
    let udp = udp_segment(V4_SRC, V4_DST, 1, 2, b"x");
    let v4 = v4_packet(17, 0, (0, 0, false), &udp);
    assert!(fragment_info(&v4).is_none());

    let packet = v6_packet(17, &udp);
    assert!(fragment_info(&packet).is_none());
}
