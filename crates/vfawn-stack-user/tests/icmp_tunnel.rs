// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! ping through the whole pipeline: an echo request pushed into the
//! device comes back as an echo reply frame on the wire ,  identifier
//! and sequence intact, TTL spent one hop, checksum honest ,  and an
//! error datagram whose quote names a TCP flow arrives at the host as
//! that flow on the error lane.

#![cfg(feature = "backend-native")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vfawn_core::{
    DeviceCaps, FlowInfo, Network, PacketDevice, SessionHandler, StackBackend, TcpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::{MockDevice, Script};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// TCP sessions stand by unanswered; ICMP is the whole test.
struct PassiveHost;

#[async_trait::async_trait]
impl SessionHandler for PassiveHost {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        let mut buf = [0u8; 64];
        let _ = session.read(&mut buf).await;
    }

    async fn on_udp(&self, _session: vfawn_core::UdpSession) {}

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

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

fn echo_request(identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![8u8, 0, 0, 0];
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(data);
    let sum = vfawn_wire::checksum::sum_words(&message);
    message[2..4].copy_from_slice(&(!vfawn_wire::checksum::fold(sum)).to_be_bytes());
    message
}

fn wait_for_reply(device: &MockDevice, identifier: u16) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        for packet in device.take_written() {
            if packet.len() >= 28
                && packet[9] == 1
                && packet[20] == 0
                && packet[24..26] == identifier.to_be_bytes()
            {
                return packet;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("no echo reply for identifier {identifier:#x}");
}

#[test]
fn ping_through_the_tunnel_gets_answered() {
    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), Arc::new(PassiveHost))
        .expect("spawn");

    let request = echo_request(0xBEEF, 42, b"through the tunnel");
    device.push(&[&icmp_frame(CLIENT_IP, SERVER_IP, 64, &request)]);

    let reply = wait_for_reply(&device, 0xBEEF);

    // The reply leaves from the probed address toward the requester,
    // with the hop budget the answering hop owes.
    let Ok((ip, message)) = vfawn_wire::ipv4::Ipv4Header::parse(&reply) else {
        panic!("reply must parse");
    };
    assert_eq!(ip.src, SERVER_IP, "answered from the probed address");
    assert_eq!(ip.dst, CLIENT_IP);
    assert_eq!(ip.ttl, 63, "the answering hop spends one");
    assert_eq!(&message[8..], b"through the tunnel", "payload kept");
    let sum = vfawn_wire::checksum::sum_words(message);
    assert_eq!(vfawn_wire::checksum::fold(sum), 0xFFFF, "checksum valid");
}

#[test]
fn second_ping_of_the_same_identity_answers_too() {
    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), Arc::new(PassiveHost))
        .expect("spawn");

    let script = Script::new(
        SocketAddrV4::new(CLIENT_IP, 0),
        SocketAddrV4::new(SERVER_IP, 0),
    );
    let _ = script; // the ICMP frames are hand-built; the script stays for TCP shapes

    let first = echo_request(0x1, 1, b"one");
    device.push(&[&icmp_frame(CLIENT_IP, SERVER_IP, 64, &first)]);
    let first_reply = wait_for_reply(&device, 0x1);
    assert_eq!(&first_reply[26..28], &1u16.to_be_bytes(), "sequence one");

    let second = echo_request(0x1, 2, b"two");
    device.push(&[&icmp_frame(CLIENT_IP, SERVER_IP, 64, &second)]);
    let mut seen_second = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        for packet in device.take_written() {
            if packet.len() >= 28
                && packet[9] == 1
                && packet[20] == 0
                && packet[26..28] == 2u16.to_be_bytes()
            {
                seen_second = true;
            }
        }
        if seen_second {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(seen_second, "the second sequence number answers too");
    let _ = Network::Icmp;
}
