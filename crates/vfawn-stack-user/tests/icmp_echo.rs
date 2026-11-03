// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The ICMP layer on the wire: an echo request through the device
//! gets its reply (identifier and sequence intact, checksum valid,
//! TTL spent one hop), and an error datagram whose quote names a flow
//! reports that flow back (RFC 792).

#![cfg(feature = "backend-native")]

use bytes::Bytes;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use vfawn_core::{FlowInfo, IcmpPacket, Network};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Answers echo requests from the device and hands error datagrams to
/// the correlation verdict; the test reads both off the counters.
/// A whole IPv4 frame around an ICMP message.
fn icmp_frame(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, message: &[u8]) -> Vec<u8> {
    vfawn_wire::emit::ipv4_frame_v4(
        src,
        dst,
        vfawn_wire::protocol::IpProtocol::Icmp,
        ttl,
        message,
    )
}

/// An echo request message with the given identity.
fn echo_request(identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![8u8, 0, 0, 0];
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(data);
    let sum = vfawn_wire::checksum::sum_words(&message);
    message[2..4].copy_from_slice(&(!vfawn_wire::checksum::fold(sum)).to_be_bytes());
    message
}

#[test]
fn echo_request_gets_its_reply() {
    // The layer is exercised directly: the shard slots are TCP-shaped,
    // and the reply is the IP frame the verdict builds, asserted byte
    // for byte below.
    let request = echo_request(0x1234, 7, b"probe-payload");
    let flow = FlowInfo {
        network: Network::Icmp,
        source: SocketAddr::V4(SocketAddrV4::new(CLIENT_IP, 0)),
        destination: SocketAddr::V4(SocketAddrV4::new(SERVER_IP, 0)),
    };
    let packet = IcmpPacket::new(flow, 8, 0, Bytes::from(request.clone())).with_ttl(64);

    let verdict = vfawn_stack_user::IcmpVerdict::from(&packet);
    let vfawn_stack_user::IcmpVerdict::EchoReply(frame) = verdict else {
        panic!("an echo request earns a reply, got {verdict:?}");
    };

    // The reply frame: from the probed address toward the requester,
    // ICMP type 0, identity and payload untouched, TTL spent one hop,
    // checksum honest (the frame parses and the message sum folds to
    // zero).
    let Ok((ip, rest)) = vfawn_wire::ipv4::Ipv4Header::parse(&frame) else {
        panic!("reply must be a parsable IPv4 frame");
    };
    assert_eq!(ip.src, SERVER_IP);
    assert_eq!(ip.dst, CLIENT_IP);
    assert_eq!(ip.ttl, 63);
    assert_eq!(rest[0], 0, "type 0: echo reply");
    assert_eq!(&rest[4..6], &0x1234u16.to_be_bytes(), "identifier kept");
    assert_eq!(&rest[6..8], &7u16.to_be_bytes(), "sequence kept");
    assert_eq!(&rest[8..], b"probe-payload");
    // A valid internet checksum folds to all-ones over the whole
    // message including the checksum field itself.
    let sum = vfawn_wire::checksum::sum_words(rest);
    assert_eq!(vfawn_wire::checksum::fold(sum), 0xFFFF, "checksum valid");
}

#[test]
fn error_quote_names_the_victim_flow() {
    // A TCP segment to quote: the original datagram's first 28 bytes.
    let mut quoted = Vec::new();
    quoted.extend_from_slice(&[0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 64, 6, 0, 0]);
    quoted.extend_from_slice(&[192, 168, 1, 100]); // requester
    quoted.extend_from_slice(&[203, 0, 113, 2]); // the peer it dialed
    quoted.extend_from_slice(&0x1234u16.to_be_bytes()); // source port
    quoted.extend_from_slice(&0x0050u16.to_be_bytes()); // destination port 80

    let mut error = vec![3u8, 4, 0, 0, 0, 0, 0, 0]; // host unreachable
    error.extend_from_slice(&quoted);
    let error = icmp_frame(Ipv4Addr::new(203, 0, 113, 1), CLIENT_IP, 64, &error);

    // The layer reads the message, not the frame's IP header.
    let Ok((_ip, message)) = vfawn_wire::ipv4::Ipv4Header::parse(&error) else {
        panic!("parsable");
    };
    let flow = FlowInfo {
        network: Network::Icmp,
        source: SocketAddr::V4(SocketAddrV4::new(CLIENT_IP, 0)),
        destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 0)),
    };
    let packet = IcmpPacket::new(flow, 3, 4, Bytes::from(message.to_vec()));
    let verdict = vfawn_stack_user::IcmpVerdict::from(&packet);
    let vfawn_stack_user::IcmpVerdict::ErrorFor(victim, code) = verdict else {
        panic!("an error quote earns a flow, got {verdict:?}");
    };
    assert_eq!(code, 4, "unreachable subtype carried");
    assert_eq!(victim.network, Network::Tcp);
    assert_eq!(
        victim.source,
        SocketAddr::new(std::net::IpAddr::V4(CLIENT_IP), 0x1234)
    );
    assert_eq!(
        victim.destination,
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 80)
    );
}
