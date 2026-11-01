// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Half-close through the in-house backend: one direction ends, the
//! other keeps carrying. The scripted client closes its write side
//! after one request; the host sees EOF on read, answers with bytes
//! written after that EOF, and the client receives them over the still
//! open server-to-client direction.

#![cfg(feature = "backend-native")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use vfawn_core::{
    DeviceCaps, FlowInfo, PacketDevice, SessionHandler, StackBackend, TcpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::{MockDevice, Script};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

struct LateResponder {
    sessions: AtomicUsize,
    reads_after_eof: AtomicUsize,
    wrote_after_eof: AtomicBool,
}

#[async_trait::async_trait]
impl SessionHandler for LateResponder {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 1024];

        // Read to the peer's EOF.
        loop {
            match session.read(&mut buf).await {
                Ok(0) => break,
                Ok(_n) => {}
                Err(_) => return,
            }
        }
        self.reads_after_eof.fetch_add(1, Ordering::SeqCst);

        // The other direction is still ours: write after seeing EOF.
        let tail = b"answered after your close";
        let peer = session.flow().source;
        let _ = session.write(tail).await;
        let _ = peer;
        self.wrote_after_eof.store(true, Ordering::SeqCst);
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
fn half_close_keeps_the_answer_direction_open() {
    let handler = Arc::new(LateResponder {
        sessions: AtomicUsize::new(0),
        reads_after_eof: AtomicUsize::new(0),
        wrote_after_eof: AtomicBool::new(false),
    });

    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    let script = Script::new(CLIENT, SERVER);
    let request = b"one request then silence";

    // Handshake.
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
    let synack = synack.expect("SYN-ACK");
    let server_seq = u32::from_be_bytes([synack[24], synack[25], synack[26], synack[27]]);

    // Establish, send the request, close our write side in the same
    // breath: the answer must still find its way back.
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x10, b"")]);
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x18, request)]);
    let client_fin_seq = 1001 + request.len() as u32;
    device.push(&[&script.tcp(client_fin_seq, server_seq.wrapping_add(1), 0x11, b"")]);

    // The host saw EOF and wrote its answer.
    wait_for(
        || handler.reads_after_eof.load(Ordering::SeqCst) >= 1,
        "host EOF",
    );
    assert!(
        handler.wrote_after_eof.load(Ordering::SeqCst),
        "the host wrote after seeing EOF"
    );

    // The answer crossed the wire toward the client.
    let answer = b"answered after your close";
    wait_for(
        || {
            device
                .take_written()
                .iter()
                .any(|p| p.len() > 40 && p[9] == 6 && &p[40..] == answer)
        },
        "late answer on the wire",
    );

    assert_eq!(handler.sessions.load(Ordering::SeqCst), 1);
}
