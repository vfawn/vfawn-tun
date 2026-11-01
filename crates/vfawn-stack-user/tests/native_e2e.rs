// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The in-house backend end to end: a scripted TCP client completes a
//! handshake through the shard skeleton, exchanges data with the host
//! handler, and both sides close. This is the A/B counterpart of the
//! ipstack backend's lifecycle test: same contract, different engine.

#![cfg(feature = "backend-native")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use vfawn_core::{
    DeviceCaps, FlowInfo, PacketDevice, SessionHandler, StackBackend, TcpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::{MockDevice, Script};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

struct EchoOnce {
    sessions: AtomicUsize,
    bytes_seen: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for EchoOnce {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 4096];
        if let Ok(n) = session.read(&mut buf).await
            && n > 0
        {
            self.bytes_seen.fetch_add(n, Ordering::SeqCst);
            let peer = session.flow().source;
            let _ = session.write(&buf[..n]).await;
            let _ = peer;
        }
        let _ = session.shutdown_write().await;
    }

    async fn on_udp(&self, _session: vfawn_core::UdpSession) {}

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
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
fn handshake_data_and_teardown_through_the_native_stack() {
    let handler = Arc::new(EchoOnce {
        sessions: AtomicUsize::new(0),
        bytes_seen: AtomicUsize::new(0),
    });

    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    let script = Script::new(CLIENT, SERVER);

    // Phase 1: SYN. The stack answers SYN-ACK on the wire. The wait
    // drains as it polls, so the SYN-ACK is caught while polling and
    // kept, not fished for again afterwards.
    device.push(&[&script.tcp(1000, 0, 0x02, b"")]);
    let mut synack = None;
    wait_for(
        || {
            let written = device.take_written();
            synack = written
                .into_iter()
                .find(|p| p.len() >= 40 && p[9] == 6 && p[33] & 0x12 == 0x12);
            synack.is_some()
        },
        "SYN-ACK",
    );
    let synack = synack.expect("SYN-ACK captured during the wait");
    let server_seq = u32::from_be_bytes([synack[24], synack[25], synack[26], synack[27]]);
    let server_ack = u32::from_be_bytes([synack[28], synack[29], synack[30], synack[31]]);
    assert_eq!(server_ack, 1001, "SYN-ACK acknowledges ISN+1");

    // Phase 2: ACK the handshake, then send data.
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x10, b"")]);
    let payload = b"through the native stack";
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x18, payload)]);

    // The host must see the session and the bytes.
    wait_for(|| handler.sessions.load(Ordering::SeqCst) >= 1, "session");
    wait_for(
        || handler.bytes_seen.load(Ordering::SeqCst) >= payload.len(),
        "payload delivery",
    );

    // The echo must come back: a data segment from the server.
    wait_for(
        || {
            device
                .take_written()
                .iter()
                .any(|p| p.len() > 40 && p[9] == 6 && &p[40..] == payload)
        },
        "echoed payload",
    );

    // Phase 3: FIN from the client. The host already shut down its
    // write side (its FIN left with the echo), so the stack's answer
    // to the client's FIN is the acknowledgment that completes the
    // close: ack advances past the FIN's sequence number.
    let client_fin_seq = 1001 + payload.len() as u32;
    device.push(&[&script.tcp(client_fin_seq, server_seq.wrapping_add(1), 0x11, b"")]);
    wait_for(
        || {
            device.take_written().iter().any(|p| {
                p.len() >= 40 && p[9] == 6 && p[33] & 0x10 == 0x10 && {
                    let ack = u32::from_be_bytes([p[28], p[29], p[30], p[31]]);
                    ack == client_fin_seq.wrapping_add(1)
                }
            })
        },
        "acknowledgment of the client FIN",
    );

    assert_eq!(handler.sessions.load(Ordering::SeqCst), 1);
    assert_eq!(
        handler.bytes_seen.load(Ordering::SeqCst),
        payload.len(),
        "exactly the payload reached the host"
    );
}
