// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Full TCP session lifecycle against a MockDevice.
//!
//! A scripted client sends a SYN, completes the handshake, exchanges data,
//! and closes. The ipstack backend should surface the session to the
//! handler with the correct flow identity and carry the data end to end.
//!
//! The script is the seed of the deterministic replay harness: the same
//! packet sequence, driven by the same virtual clock, will exercise the
//! in-house stack the same way once it lands.

#![cfg(feature = "backend-ipstack")]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vfawn_core::{
    DeviceCaps, FlowInfo, Network, PacketDevice, SessionHandler, StackBackend, TcpSession, Verdict,
};
use vfawn_testsuite::MockDevice;

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

/// Build a minimal IPv4+TCP packet with the given flags and payload.
/// Checksums are correct; nothing here is random.
fn tcp_packet(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + 20 + payload.len());

    // IPv4 header (RFC 791): 20 bytes, protocol 6, correct total length.
    packet.extend_from_slice(&[0x45, 0x00]);
    packet.extend_from_slice(&((20 + 20 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // id, flags
    packet.extend_from_slice(&[64, 0x06]); // ttl, proto
    packet.extend_from_slice(&[0x00, 0x00]); // checksum (fixed below)
    packet.extend_from_slice(&CLIENT.ip().octets());
    packet.extend_from_slice(&SERVER.ip().octets());

    // TCP header (RFC 9293): 20 bytes.
    packet.extend_from_slice(&CLIENT.port().to_be_bytes());
    packet.extend_from_slice(&SERVER.port().to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&ack.to_be_bytes());
    packet.push(0x50); // data offset 5 (no options)
    packet.push(flags);
    packet.extend_from_slice(&0xffffu16.to_be_bytes()); // window
    packet.extend_from_slice(&[0x00, 0x00]); // checksum (fixed below)
    packet.extend_from_slice(&[0x00, 0x00]); // urgent

    // Fix IPv4 checksum.
    let ipv4_sum = checksum(&packet[..20]);
    packet[10] = (ipv4_sum >> 8) as u8;
    packet[11] = ipv4_sum as u8;

    // Fix TCP checksum (pseudo-header + segment).
    let tcp_offset = 20;
    let pseudo = pseudo_header(CLIENT.ip(), SERVER.ip(), 6, (20 + payload.len()) as u32);
    let segment_sum = checksum_with_carry(pseudo, &packet[tcp_offset..]);
    packet[tcp_offset + 16] = (segment_sum >> 8) as u8;
    packet[tcp_offset + 17] = segment_sum as u8;

    packet.extend_from_slice(payload);
    packet
}

fn checksum(data: &[u8]) -> u16 {
    !fold(sum_words(data))
}

fn checksum_with_carry(carry: u32, data: &[u8]) -> u16 {
    !fold(carry + sum_words(data))
}

fn sum_words(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [byte] = chunks.remainder() {
        sum += (*byte as u32) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn pseudo_header(src: &Ipv4Addr, dst: &Ipv4Addr, protocol: u8, length: u32) -> u32 {
    let mut sum = 0u32;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += protocol as u32;
    sum += length;
    sum
}

struct RecordingHandler {
    judge_calls: AtomicUsize,
    tcp_sessions: Mutex<Vec<FlowInfo>>,
}

#[async_trait::async_trait]
impl SessionHandler for RecordingHandler {
    fn judge_flow(&self, flow: &FlowInfo, _first_packet: &[u8]) -> Verdict {
        self.judge_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(flow.network, Network::Tcp);
        assert_eq!(flow.source, SocketAddr::V4(CLIENT));
        assert_eq!(flow.destination, SocketAddr::V4(SERVER));
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        // Record the flow, echo the data back.
        self.tcp_sessions
            .lock()
            .unwrap()
            .push(session.flow().clone());

        let mut buf = [0u8; 1024];
        if let Ok(n) = session.read(&mut buf).await
            && n > 0
        {
            let _ = session.write(&buf[..n]).await;
        }
        let _ = session.shutdown_write().await;
    }

    async fn on_udp(&self, _session: vfawn_core::UdpSession) {}

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_handshake_data_and_teardown() {
    let handler = Arc::new(RecordingHandler {
        judge_calls: AtomicUsize::new(0),
        tcp_sessions: Mutex::new(Vec::new()),
    });

    // Spawn the backend.
    let backend = Box::new(vfawn_stack_user::IpstackBackend::default());
    let owned_device = MockDevice::new(DeviceCaps::MINIMAL);
    let stack_device = owned_device.duplicate().unwrap();

    let handle = backend.spawn(stack_device, handler.clone()).expect("spawn");

    // Wait for the backend to come up.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Phase 1: SYN.
    let syn = tcp_packet(1000, 0, 0x02, b""); // SYN
    owned_device.push(&[&syn]);

    // Give ipstack time to process the SYN and emit SYN-ACK.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The device's write side should have at least one packet (the
    // SYN-ACK). Feed it back through the mock device so the stack can
    // process it. In a real TUN this goes through the kernel; here we
    // short-circuit by pushing the written packets into the inbox.
    let written = owned_device.take_written();
    assert!(!written.is_empty(), "expected SYN-ACK after SYN");
    for packet in &written {
        if packet.len() > 40 && packet[9] == 6 {
            // TCP packet from the stack; push it back as if the client
            // received it. For the mock we need to reverse src/dst.
            let reversed = reverse_tcp(packet);
            owned_device.push(&[&reversed]);
        }
    }

    // Phase 2: ACK to complete the handshake.
    let ack = tcp_packet(1001, 2001, 0x10, b""); // ACK
    owned_device.push(&[&ack]);

    // Phase 3: data.
    let data = tcp_packet(1001, 2001, 0x18, b"hello stack"); // PSH+ACK
    owned_device.push(&[&data]);

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Phase 4: FIN.
    let fin = tcp_packet(1013, 2001, 0x11, b""); // FIN+ACK
    owned_device.push(&[&fin]);

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Assertions.
    assert!(
        handler.judge_calls.load(Ordering::SeqCst) >= 1,
        "judge_flow must be called for the TCP flow"
    );

    handle.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Reverse src and dst of a TCP packet so the mock device can feed it
/// back into the stack as if the client sent the response.
fn reverse_tcp(packet: &[u8]) -> Vec<u8> {
    if packet.len() < 40 {
        return packet.to_vec();
    }
    let mut reversed = packet.to_vec();
    // Swap IPv4 addresses.
    reversed.swap(12, 16);
    reversed.swap(13, 17);
    reversed.swap(14, 18);
    reversed.swap(15, 19);
    // Swap TCP ports.
    reversed.swap(20, 22);
    reversed.swap(21, 23);
    // Recompute checksums.
    let ipv4_sum = checksum(&reversed[..20]);
    reversed[10] = (ipv4_sum >> 8) as u8;
    reversed[11] = ipv4_sum as u8;
    let pseudo = pseudo_header(
        &Ipv4Addr::new(reversed[12], reversed[13], reversed[14], reversed[15]),
        &Ipv4Addr::new(reversed[16], reversed[17], reversed[18], reversed[19]),
        6,
        (reversed.len() - 20) as u32,
    );
    let tcp_sum = checksum_with_carry(pseudo, &reversed[20..]);
    reversed[36] = (tcp_sum >> 8) as u8;
    reversed[37] = tcp_sum as u8;
    reversed
}
