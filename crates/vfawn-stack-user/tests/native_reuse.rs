// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A closed connection gives its four-tuple back. A client that churns
//! short connections reuses source ports, and a SYN that lands on the
//! remains of an earlier connection must open a new one instead of
//! vanishing (the Windows retest's churn stall, N-07). gVisor, the
//! stack sing-tun runs, unregisters an endpoint the moment it closes
//! (`connect.go` `cleanupLocked`), and in TIME-WAIT hands a SYN above
//! the old receive cursor to a new connection (`rcv.go`
//! `handleTimeWaitSegment`, RFC 1122 4.2.2.13).

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

const SYN: u8 = 0x02;
const FIN: u8 = 0x01;
const ACK: u8 = 0x10;

/// Who closes first decides the server's last state: the passive
/// closer ends in LAST-ACK, the active closer in TIME-WAIT.
#[derive(Clone, Copy)]
enum Closer {
    Client,
    Server,
}

struct Counting {
    closer: Closer,
    judged: AtomicUsize,
    sessions: AtomicUsize,
}

impl Counting {
    fn new(closer: Closer) -> Arc<Self> {
        Arc::new(Self {
            closer,
            judged: AtomicUsize::new(0),
            sessions: AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl SessionHandler for Counting {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        self.judged.fetch_add(1, Ordering::SeqCst);
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 256];
        if let Closer::Client = self.closer {
            while let Ok(n) = session.read(&mut buf).await
                && n > 0
            {}
        }
        let _ = session.shutdown_write().await;
        while let Ok(n) = session.read(&mut buf).await
            && n > 0
        {}
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

fn flags(packet: &[u8]) -> u8 {
    packet[33]
}

fn seq(packet: &[u8]) -> u32 {
    u32::from_be_bytes([packet[24], packet[25], packet[26], packet[27]])
}

/// The first segment the server wrote whose flags include `wanted`.
fn await_segment(device: &MockDevice, wanted: u8, what: &str) -> Vec<u8> {
    let mut found = None;
    wait_for(
        || {
            found = device
                .take_written()
                .into_iter()
                .find(|p| p.len() >= 40 && p[9] == 6 && flags(p) & wanted == wanted);
            found.is_some()
        },
        what,
    );
    found.expect("the segment")
}

/// The end of one connection: the client's send cursor and the
/// server's ISN.
struct Ends {
    client_next: u32,
    server_isn: u32,
}

/// One whole connection from `isn`, closed by `closer`, every
/// segment answered.
fn one_connection(device: &MockDevice, script: &Script, isn: u32, closer: Closer) -> Ends {
    device.push(&[&script.tcp(isn, 0, SYN, b"")]);
    let server_isn = seq(&await_segment(device, SYN | ACK, "SYN-ACK"));
    let mut ours = isn.wrapping_add(1);
    let theirs = server_isn.wrapping_add(1);
    device.push(&[&script.tcp(ours, theirs, ACK, b"")]);
    match closer {
        Closer::Client => {
            // Our FIN first; the server answers with its own (LAST-ACK)
            // and our ACK of it ends the connection.
            device.push(&[&script.tcp(ours, theirs, FIN | ACK, b"")]);
            ours = ours.wrapping_add(1);
            let fin = await_segment(device, FIN, "the server's FIN");
            device.push(&[&script.tcp(ours, seq(&fin).wrapping_add(1), ACK, b"")]);
        }
        Closer::Server => {
            // The server's FIN first; we acknowledge it and close too,
            // which leaves the server in TIME-WAIT.
            let fin = await_segment(device, FIN, "the server's FIN");
            let after = seq(&fin).wrapping_add(1);
            device.push(&[&script.tcp(ours, after, ACK, b"")]);
            device.push(&[&script.tcp(ours, after, FIN | ACK, b"")]);
            ours = ours.wrapping_add(1);
            await_segment(device, ACK, "the ACK of our FIN");
        }
    }
    Ends {
        client_next: ours,
        server_isn,
    }
}

fn the_port_reopens(closer: Closer) {
    let handler = Counting::new(closer);
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = Box::new(NativeBackend::default())
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");
    let script = Script::new(CLIENT, SERVER);

    let first = one_connection(&device, &script, 1000, closer);
    wait_for(
        || handler.sessions.load(Ordering::SeqCst) == 1,
        "the first session",
    );
    std::thread::sleep(Duration::from_millis(50));

    // The same four-tuple again, its ISN above everything the first
    // connection used (RFC 1122 4.2.2.13's condition for TIME-WAIT).
    let second = one_connection(
        &device,
        &script,
        first.client_next.wrapping_add(100_000),
        closer,
    );
    // And ours above everything we used: the old ISN, its SYN and FIN.
    let ahead = second.server_isn.wrapping_sub(first.server_isn);
    assert!(
        ahead > 1 && ahead < u32::MAX / 2,
        "the server ISN must climb past the old FIN: {} -> {}",
        first.server_isn,
        second.server_isn
    );
    wait_for(
        || handler.sessions.load(Ordering::SeqCst) == 2,
        "a second session on the reused port",
    );
    assert_eq!(handler.judged.load(Ordering::SeqCst), 2);
}

#[test]
fn a_port_closed_by_the_client_reopens() {
    the_port_reopens(Closer::Client);
}

#[test]
fn a_port_closed_by_the_server_reopens_from_time_wait() {
    the_port_reopens(Closer::Server);
}

/// A segment for a connection the stack no longer knows is not a
/// connection request: gVisor's forwarder takes only SYNs
/// (`forwarder.go` `HandlePacket`), so the host never judges it.
#[test]
fn a_stray_segment_never_reaches_the_judge() {
    let handler = Counting::new(Closer::Client);
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = Box::new(NativeBackend::default())
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");
    let script = Script::new(CLIENT, SERVER);

    device.push(&[&script.tcp(7000, 9000, FIN | ACK, b"")]);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(handler.judged.load(Ordering::SeqCst), 0);

    // Nor does it squat on the four-tuple.
    one_connection(&device, &script, 1000, Closer::Client);
    wait_for(
        || handler.sessions.load(Ordering::SeqCst) == 1,
        "a session after the stray",
    );
}
