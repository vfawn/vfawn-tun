// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A TCP handshake over IPv6, end to end: SYN answers SYN-ACK on the
//! wire as a valid v6 frame, the handshake completes, payload crosses
//! to the session, and the echo rides back with a verifiable
//! pseudo-header checksum.

#![cfg(feature = "backend-native")]

use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use vfawn_core::{
    DeviceCaps, FlowInfo, PacketDevice, SessionHandler, StackBackend, TcpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::MockDevice;

const CLIENT: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 45678, 0, 0);
const SERVER: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 443, 0, 0);
const PAYLOAD: &[u8] = b"tcp rides v6";

struct V6Echo {
    sessions: AtomicUsize,
    bytes: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for V6Echo {
    fn judge_flow(&self, flow: &FlowInfo, _first: &[u8]) -> Verdict {
        assert_eq!(flow.source, std::net::SocketAddr::V6(CLIENT));
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let mut buffer = [0u8; 256];
        if let Ok(n) = session.read(&mut buffer).await
            && n > 0
        {
            self.bytes.fetch_add(n, Ordering::SeqCst);
            let _ = session.write(&buffer[..n]).await;
        }
        let _ = session.shutdown_write().await;
    }

    async fn on_udp(&self, _session: vfawn_core::UdpSession) {}
    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

/// One TCP-over-v6 segment with a valid checksum.
fn segment(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&CLIENT.port().to_be_bytes());
    tcp.extend_from_slice(&SERVER.port().to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(5 << 4); // data offset: no options
    tcp.push(flags);
    tcp.extend_from_slice(&64256u16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    let sum = vfawn_wire::checksum::pseudo_header_v6(
        *CLIENT.ip(),
        *SERVER.ip(),
        vfawn_wire::protocol::IpProtocol::Tcp,
        tcp.len() as u32,
    ) + vfawn_wire::checksum::sum_words(&tcp);
    let fixed = !vfawn_wire::checksum::fold(sum);
    tcp[16..18].copy_from_slice(&fixed.to_be_bytes());
    vfawn_wire::emit::ipv6_frame_v6(
        *CLIENT.ip(),
        *SERVER.ip(),
        vfawn_wire::protocol::IpProtocol::Tcp,
        64,
        &tcp,
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

/// The server's sequence in a captured v6 TCP frame.
fn frame_seq(frame: &[u8]) -> u32 {
    u32::from_be_bytes([frame[44], frame[45], frame[46], frame[47]])
}

#[test]
fn a_tcp_handshake_and_exchange_over_v6() {
    let handler = Arc::new(V6Echo {
        sessions: AtomicUsize::new(0),
        bytes: AtomicUsize::new(0),
    });
    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    // SYN (seq 1000).
    device.push(&[&segment(1000, 0, 0x02, b"")]);
    let mut synack = None;
    wait_for(
        || {
            synack = device.take_written().into_iter().find(|frame| {
                frame.first().map(|b| b >> 4) == Some(6)
                    && frame[6] == 6
                    && frame.len() > 60
                    && frame[53] & 0x12 == 0x12
            });
            synack.is_some()
        },
        "the v6 SYN-ACK",
    );
    let synack = synack.expect("kept");
    let server_seq = frame_seq(&synack);
    // The SYN-ACK's checksum verifies.
    let (header, message) = vfawn_wire::ipv6::Ipv6Header::parse(&synack).expect("v6 header");
    let sum = vfawn_wire::checksum::pseudo_header_v6(
        header.src,
        header.dst,
        vfawn_wire::protocol::IpProtocol::Tcp,
        message.len() as u32,
    ) + vfawn_wire::checksum::sum_words(message);
    assert_eq!(vfawn_wire::checksum::fold(sum), 0xffff);
    assert_eq!(header.src, *SERVER.ip(), "answered from the server");

    // Complete the handshake, then send data.
    device.push(&[&segment(1001, server_seq.wrapping_add(1), 0x10, b"")]);
    device.push(&[&segment(1001, server_seq.wrapping_add(1), 0x18, PAYLOAD)]);

    wait_for(
        || handler.sessions.load(Ordering::SeqCst) >= 1,
        "the session",
    );
    wait_for(
        || handler.bytes.load(Ordering::SeqCst) >= PAYLOAD.len(),
        "the payload",
    );

    // The echo: a v6 TCP frame carrying the payload back.
    let mut echoed = None;
    wait_for(
        || {
            echoed = device.take_written().into_iter().find(|frame| {
                frame.first().map(|b| b >> 4) == Some(6)
                    && frame[6] == 6
                    && frame.len() >= 40 + 20 + PAYLOAD.len()
                    && &frame[40 + 20..frame.len().min(40 + 20 + PAYLOAD.len())] == PAYLOAD
            });
            echoed.is_some()
        },
        "the v6 echo",
    );
    let echoed = echoed.expect("kept");
    let (header, message) = vfawn_wire::ipv6::Ipv6Header::parse(&echoed).expect("v6 header");
    let sum = vfawn_wire::checksum::pseudo_header_v6(
        header.src,
        header.dst,
        vfawn_wire::protocol::IpProtocol::Tcp,
        message.len() as u32,
    ) + vfawn_wire::checksum::sum_words(message);
    assert_eq!(
        vfawn_wire::checksum::fold(sum),
        0xffff,
        "the echo's checksum verifies"
    );
}
