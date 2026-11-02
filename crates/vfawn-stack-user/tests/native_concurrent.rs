// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Concurrency through the in-house backend: eight clients at once,
//! each holding its session open while the others run. A handler that
//! outlives its first bytes (any relay does) must not occupy the
//! handoff lane, or every flow after the first starves.

#![cfg(feature = "backend-native")]

use std::collections::HashSet;
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
const CLIENTS: usize = 8;

/// Reads until the peer closes, then answers: a long-lived handler in
/// the relay's shape, not the read-once shape the early e2e used.
struct AnswerAtClose {
    sessions: AtomicUsize,
    answered: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for AnswerAtClose {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 1024];
        loop {
            match session.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => return,
            }
        }
        let answer = b"late answer";
        let _ = session.write(answer).await;
        let _ = session.shutdown_write().await;
        self.answered.fetch_add(1, Ordering::SeqCst);
    }

    async fn on_udp(&self, _session: vfawn_core::UdpSession) {}

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

fn wait_for<F: FnMut() -> bool>(mut predicate: F, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

/// The client port a TCP packet toward a client carries (IP dst port
/// in the TCP header), for telling the eight flows apart on one wire.
fn dst_port_of(packet: &[u8]) -> Option<u16> {
    if packet.len() < 24 || packet[9] != 6 {
        return None;
    }
    Some(u16::from_be_bytes([packet[22], packet[23]]))
}

#[test]
fn eight_sessions_hold_open_concurrently() {
    let handler = Arc::new(AnswerAtClose {
        sessions: AtomicUsize::new(0),
        answered: AtomicUsize::new(0),
    });

    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    // Eight clients, one wire, one orchestrating thread (the device's
    // queues are shared, so one reader keeps every reply accounted).
    let scripts: Vec<(u16, Script)> = (0..CLIENTS)
        .map(|index| {
            let client = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 40000 + index as u16);
            (client.port(), Script::new(client, SERVER))
        })
        .collect();

    // Handshakes, all at once.
    let mut syns: Vec<Vec<u8>> = Vec::new();
    for (_, script) in &scripts {
        syns.push(script.tcp(1000, 0, 0x02, b""));
    }
    let refs: Vec<&[u8]> = syns.iter().map(|p| p.as_slice()).collect();
    device.push(&refs);

    let mut server_seqs: Vec<(u16, u32)> = Vec::new();
    wait_for(
        || {
            for packet in device.take_written() {
                if packet.len() >= 40
                    && packet[9] == 6
                    && packet[33] & 0x12 == 0x12
                    && let Some(port) = dst_port_of(&packet)
                    && !server_seqs.iter().any(|(p, _)| *p == port)
                {
                    let seq = u32::from_be_bytes([packet[24], packet[25], packet[26], packet[27]]);
                    server_seqs.push((port, seq));
                }
            }
            server_seqs.len() == CLIENTS
        },
        "eight SYN-ACKs",
    );
    server_seqs.sort_by_key(|(port, _)| *port);

    // Establish all eight, then data on each: the sessions all live at
    // once, held open by the handler's read-until-close. Both lists
    // are in ascending client-port order, so the pairing is by index.
    let mut established: Vec<(u16, u32)> = Vec::new();
    for (index, (_, script)) in scripts.iter().enumerate() {
        let (port, seq) = server_seqs[index];
        device.push(&[&script.tcp(1001, seq.wrapping_add(1), 0x10, b"")]);
        let payload = format!("client {index} request").into_bytes();
        device.push(&[&script.tcp(1001, seq.wrapping_add(1), 0x18, &payload)]);
        established.push((port, 1001 + payload.len() as u32));
    }
    wait_for(
        || handler.sessions.load(Ordering::SeqCst) >= CLIENTS,
        "eight live sessions",
    );

    // Staggered closes: each session held open a different span while
    // the others keep theirs, then the late answers must all arrive.
    for (index, (_, script)) in scripts.iter().enumerate() {
        let (port, fin_seq) = established[index];
        let seq = server_seqs
            .iter()
            .find(|(p, _)| *p == port)
            .map(|(_, s)| *s)
            .expect("server seq");
        std::thread::sleep(Duration::from_millis(30));
        device.push(&[&script.tcp(fin_seq, seq.wrapping_add(1), 0x11, b"")]);
    }

    let mut answered_ports: HashSet<u16> = HashSet::new();
    wait_for(
        || {
            for packet in device.take_written() {
                if packet.len() > 40
                    && packet[9] == 6
                    && &packet[40..] == b"late answer"
                    && let Some(port) = dst_port_of(&packet)
                {
                    answered_ports.insert(port);
                }
            }
            answered_ports.len() == CLIENTS
        },
        "eight late answers",
    );

    assert_eq!(handler.sessions.load(Ordering::SeqCst), CLIENTS);
    assert_eq!(handler.answered.load(Ordering::SeqCst), CLIENTS);
}
