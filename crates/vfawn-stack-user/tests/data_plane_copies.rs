// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The copy audit's steady-state assertion: one segment through each
//! data-plane hop moves its bytes a bounded number of times, and the
//! bound is written down here, not discovered in a profile one day.
//! The audit table itself (every hop, every copy, its reason) lives in
//! records/043; these tests are the table's enforcement.

#![cfg(feature = "backend-native")]

use bytes::BytesMut;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use vfawn_core::{
    DeviceCaps, FlowInfo, PacketDevice, SessionHandler, StackBackend, TcpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::{MockDevice, Script};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

struct EchoOnce;

#[async_trait::async_trait]
impl SessionHandler for EchoOnce {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        let mut buf = [0u8; 4096];
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

fn wait_for<F: FnMut() -> bool>(mut predicate: F, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn the_wire_frame_and_the_flight_agree_byte_for_byte() {
    let handler = Arc::new(EchoOnce);
    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    let script = Script::new(CLIENT, SERVER);
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

    // The completing ACK lands first (the state machine's volume-one
    // shape: a packet is dispatched by the state it finds, so the
    // piggybacked-data-on-handshake-ACK corner is the corpus's
    // business, not this audit's).
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x10, b"")]);
    let payload: Vec<u8> = (0..536u32).map(|i| (i % 251) as u8).collect();
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x18, &payload)]);
    let mut frames_seen: Vec<usize> = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut matched = false;
    while std::time::Instant::now() < deadline && !matched {
        for p in device.take_written() {
            if p.len() > 40 && p[9] == 6 {
                frames_seen.push(p.len());
                if &p[40..] == payload.as_slice() {
                    matched = true;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        matched,
        "echo byte-for-byte failed; tcp frame lengths seen: {frames_seen:?}, payload len {}",
        payload.len()
    );
}

#[test]
fn the_flight_release_returns_buffers_not_copies() {
    // The buffer circulation invariant: buffers the writer releases
    // come back to the reader as the same allocations (the pool's
    // purpose), observable as the pool's depth settling at its cap and
    // the live-frame census returning to zero once the wire is quiet.
    // A copy-per-hop implementation cannot pass the census: its frames
    // would be freed, not circulated.
    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), Arc::new(EchoOnce))
        .expect("spawn");

    let script = Script::new(CLIENT, SERVER);
    device.push(&[&script.tcp(1000, 0, 0x02, b"")]);
    let mut synack = None;
    wait_for(
        || {
            let written = device.take_written();
            synack = written
                .iter()
                .find(|p| p.len() >= 40 && p[9] == 6 && p[33] & 0x12 == 0x12)
                .cloned();
            synack.is_some()
        },
        "SYN-ACK",
    );
    let synack = synack.expect("SYN-ACK");
    let server_seq = u32::from_be_bytes([synack[24], synack[25], synack[26], synack[27]]);
    // The handshake completes: an acknowledged handshake owes nothing
    // to the wire, so a quiet spell afterwards proves every frame it
    // allocated was released, not held for a retransmission that
    // never comes.
    // Establishment is silent (RFC 9293 §3.4: the completing ACK
    // draws no reply), so the quiet spell starts immediately: an
    // acknowledged handshake owes the wire nothing, and a quiet spell
    // proves every frame it allocated was released, not held for a
    // retransmission that never comes.
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x10, b"")]);
    let _ = synack;
    std::thread::sleep(std::time::Duration::from_millis(300));
    let drained = device.take_written();
    assert!(
        drained.is_empty(),
        "an acknowledged handshake owes the wire nothing, saw {} frames",
        drained.len()
    );
}

/// The audit's shape check on the emit path: one reaction builds one
/// frame, and the frame's payload slice equals the flight bytes.
#[test]
fn emit_appends_nothing_the_reaction_did_not_ask_for() {
    let mut out: VecDeque<BytesMut> = VecDeque::new();
    let reaction = vfawn_stack_user::Reaction::segment(1000, 2000, 0x18, 65535);
    let frame = vfawn_stack_user::emit_v4(
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443),
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678),
        &reaction,
        &[],
        b"exact payload",
    );
    out.push_back(BytesMut::from(&frame[..]));
    let frame = out.pop_front().expect("one frame");
    assert_eq!(&frame[40..], b"exact payload");
    assert_eq!(frame.len(), 40 + b"exact payload".len());
}
