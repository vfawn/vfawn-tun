// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! An ICMPv6 echo through the native stack: the request answers as a
//! type-129 reply whose mandatory checksum verifies, and the reply's
//! bytes are the request's own identifier, sequence, and data.

#![cfg(feature = "backend-native")]

use std::net::{Ipv6Addr, SocketAddrV6};
use std::time::Duration;

use vfawn_core::{DeviceCaps, PacketDevice, StackBackend};
use vfawn_testsuite::MockDevice;

const CLIENT: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
const SERVER: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

/// One ICMPv6 echo request with a valid pseudo-header checksum.
fn echo_request(identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(8 + data.len());
    message.extend_from_slice(&[128, 0, 0, 0]); // echo request, code 0
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(data);
    let sum = vfawn_wire::checksum::pseudo_header_v6(
        CLIENT,
        SERVER,
        vfawn_wire::protocol::IpProtocol::Icmpv6,
        message.len() as u32,
    ) + vfawn_wire::checksum::sum_words(&message);
    message[2..4].copy_from_slice(&(!vfawn_wire::checksum::fold(sum)).to_be_bytes());
    vfawn_wire::emit::ipv6_frame_v6(
        CLIENT,
        SERVER,
        vfawn_wire::protocol::IpProtocol::Icmpv6,
        64,
        &message,
    )
}

fn wait_for<F: FnMut() -> bool>(mut predicate: F, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn an_icmpv6_echo_answers_with_a_verifiable_reply() {
    let device = MockDevice::new(DeviceCaps::MINIMAL);

    // The datagram slot needs the stack to exist; a bare shard bed
    // with the native backend is the whole pipeline.
    let handler = std::sync::Arc::new(Noop);
    let backend = Box::new(vfawn_stack_user::NativeBackend::default());
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler)
        .expect("spawn native backend");

    let request = echo_request(0x2211, 7, b"v6 ping");
    device.push(&[&request]);

    // The reply: an ICMPv6 frame whose message is the request with
    // the type flipped, checksum honestly recomputed.
    let mut reply = None;
    wait_for(
        || {
            reply = device.take_written().into_iter().find(|frame| {
                frame.first().map(|b| b >> 4) == Some(6) && frame.len() > 40 && frame[6] == 58
            });
            reply.is_some()
        },
        "the echo reply",
    );
    let reply = reply.expect("the wait kept the frame");

    let (header, message) = vfawn_wire::ipv6::Ipv6Header::parse(&reply).expect("v6 header");
    assert_eq!(header.src, SERVER, "answered from the address asked");
    assert_eq!(header.dst, CLIENT);
    assert_eq!(header.hop_limit, 63, "one hop of budget spent");
    assert_eq!(message[0], 129, "the echo reply type");
    // The checksum verifies: pseudo-header plus message folds to ones.
    let sum = vfawn_wire::checksum::pseudo_header_v6(
        header.src,
        header.dst,
        vfawn_wire::protocol::IpProtocol::Icmpv6,
        message.len() as u32,
    ) + vfawn_wire::checksum::sum_words(message);
    assert_eq!(vfawn_wire::checksum::fold(sum), 0xffff);
    // Identifier, sequence, and data ride unchanged.
    assert_eq!(&message[4..6], &0x2211u16.to_be_bytes());
    assert_eq!(&message[6..8], &7u16.to_be_bytes());
    assert_eq!(&message[8..], b"v6 ping");
    let _ = SocketAddrV6::new(CLIENT, 0, 0, 0);
}

struct Noop;

#[async_trait::async_trait]
impl vfawn_core::SessionHandler for Noop {
    fn judge_flow(&self, _flow: &vfawn_core::FlowInfo, _first: &[u8]) -> vfawn_core::Verdict {
        vfawn_core::Verdict::Accept
    }
    async fn on_tcp(&self, _session: vfawn_core::TcpSession) {}
    async fn on_udp(&self, _session: vfawn_core::UdpSession) {}
    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}
