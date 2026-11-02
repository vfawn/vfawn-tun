// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The SYN-flood posture end to end: ten thousand spoofed SYNs from as
//! many flows, then one legitimate client that must still complete a
//! handshake and exchange data. What the flood may cost is shard
//! slots; what it may never cost is a host session, a channel, or the
//! legitimate connection (RFC 4987 §3.3's cookie promise).

#![cfg(feature = "backend-native")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vfawn_core::{
    DeviceCaps, FlowInfo, PacketDevice, SessionHandler, StackBackend, TcpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::{MockDevice, Script};

const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

struct Echo {
    sessions: AtomicUsize,
    bytes_seen: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for Echo {
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
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn syn_flood_costs_slots_but_never_a_session_or_a_connection() {
    let handler = Arc::new(Echo {
        sessions: AtomicUsize::new(0),
        bytes_seen: AtomicUsize::new(0),
    });

    // Cookie mode is the default posture; the flood rides exactly what
    // a real deployment would run.
    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    // The flood: every SYN its own flow, so every one costs a slot.
    const FLOOD: usize = 10_000;
    let mut flood: Vec<Vec<u8>> = Vec::with_capacity(FLOOD);
    for index in 0..FLOOD {
        let spoofed = SocketAddrV4::new(
            Ipv4Addr::new(203, 0, 113, (index % 200) as u8 + 20),
            1024 + (index % 60_000) as u16,
        );
        let script = Script::new(spoofed, SERVER);
        flood.push(script.tcp(1000, 0, 0x02, b""));
    }
    let refs: Vec<&[u8]> = flood.iter().map(|p| p.as_slice()).collect();
    device.push(&refs);

    // Every SYN is answered (a cookie costs a SYN-ACK and nothing
    // else), and no flood flow ever became a session: the host sees
    // nothing while ten thousand handshakes hang half-open.
    let mut synacks = 0;
    wait_for(
        || {
            synacks += device
                .take_written()
                .iter()
                // TCP with the SYN bit set: the SYN-ACKs of the flood.
                .filter(|p| p.len() >= 40 && p[9] == 6 && p[33] & 0x02 == 0x02)
                .count();
            synacks >= FLOOD
        },
        "every flooded SYN answered",
    );
    assert_eq!(handler.sessions.load(Ordering::SeqCst), 0);

    // The legitimate client: ordinary handshake, data, echo.
    let client = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
    let script = Script::new(client, SERVER);
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
        "legitimate SYN-ACK",
    );
    let synack = synack.expect("SYN-ACK captured during the wait");
    let server_seq = u32::from_be_bytes([synack[24], synack[25], synack[26], synack[27]]);

    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x10, b"")]);
    let payload = b"the one real connection";
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x18, payload)]);

    wait_for(|| handler.sessions.load(Ordering::SeqCst) >= 1, "session");
    wait_for(
        || {
            device
                .take_written()
                .iter()
                .any(|p| p.len() > 40 && p[9] == 6 && &p[40..] == payload)
        },
        "echoed payload",
    );

    assert_eq!(handler.sessions.load(Ordering::SeqCst), 1);
    assert_eq!(
        handler.bytes_seen.load(Ordering::SeqCst),
        payload.len(),
        "exactly the legitimate bytes reached the host"
    );
}
