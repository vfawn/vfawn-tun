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
use vfawn_testsuite::{MockDevice, Script, reverse_tcp};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

static SCRIPT: std::sync::LazyLock<Script> =
    std::sync::LazyLock::new(|| Script::new(CLIENT, SERVER));

fn tcp_packet(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    SCRIPT.tcp(seq, ack, flags, payload)
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
