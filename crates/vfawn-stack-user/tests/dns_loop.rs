// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! DNS hijack end to end: a query aimed at any resolver, a session
//! aimed at ours, an answer that comes back from the resolver the
//! client asked for.
//!
//! The packets are dig-shaped (UDP) and resolver-shaped (TCP): a port-53
//! flow enters the mock device toward a far address, the bridge rewrites
//! the destination to the virtual resolver before the stack sees it,
//! the handler receives a session toward the virtual address, and the
//! reply the stack writes carries the original resolver address as its
//! source, checksums intact. The same walk runs for a TCP handshake's
//! first answer, which is where a TCP rewrite bug would first show.

#![cfg(feature = "backend-ipstack")]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vfawn_core::{
    DeviceCaps, DnsHijack, FlowInfo, PacketDevice, SessionHandler, StackBackend, TcpSession,
    UdpSession, Verdict,
};
use vfawn_testsuite::{MockDevice, Script};
use vfawn_wire::checksum::verify_transport_v4;
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::protocol::IpProtocol;
use vfawn_wire::udp::UdpHeader;

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 50000);
const RESOLVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53);
const VIRTUAL: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

struct ResolvingHost {
    sessions: AtomicUsize,
    seen_destination: std::sync::Mutex<Vec<SocketAddr>>,
}

#[async_trait::async_trait]
impl SessionHandler for ResolvingHost {
    fn judge_flow(&self, _flow: &FlowInfo, _first_packet: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_udp(&self, mut session: UdpSession) {
        // The host is the resolver: it sees the virtual address and
        // answers there; the mapping back is the bridge's job.
        self.seen_destination
            .lock()
            .unwrap()
            .push(session.flow().destination);
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 512];
        if let Ok((n, peer)) = session.recv(&mut buf).await {
            let _ = session.send(&buf[..n], &peer).await;
        }
    }

    async fn on_tcp(&self, _session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
    }

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

fn hijacking_backend() -> (Box<vfawn_stack_user::IpstackBackend>, Arc<ResolvingHost>) {
    let host = Arc::new(ResolvingHost {
        sessions: AtomicUsize::new(0),
        seen_destination: std::sync::Mutex::new(Vec::new()),
    });
    let backend = Box::new(vfawn_stack_user::IpstackBackend {
        dns: Arc::new(DnsHijack::new(Some(VIRTUAL), None)),
        ..vfawn_stack_user::IpstackBackend::default()
    });
    (backend, host)
}

fn wait_for<F: Fn() -> bool>(predicate: F, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

/// Poll the device's write side without losing packets to the polling.
fn collect_written(device: &MockDevice, what: &str) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let written = device.take_written();
        if !written.is_empty() {
            return written;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "current_thread")]
async fn udp_query_round_trips_through_the_virtual_resolver() {
    let (backend, host) = hijacking_backend();
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = backend
        .spawn(device.duplicate().unwrap(), host.clone())
        .expect("spawn");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A dig-shaped query aimed at a public resolver.
    let script = Script::new(CLIENT, RESOLVER);
    let query = script.udp(b"\x12\x34\x01\x00\x00\x01\x00\x00");
    device.push(&[&query]);

    wait_for(|| host.sessions.load(Ordering::SeqCst) > 0, "the session");
    // Then the reply must appear on the device's write side.
    let reply = collect_written(&device, "the written reply");
    handle.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        host.seen_destination.lock().unwrap().as_slice(),
        &[SocketAddr::V4(SocketAddrV4::new(VIRTUAL, 53))],
        "the host faced the virtual resolver"
    );

    let reply = reply
        .into_iter()
        .find(|p| p.len() > 20 && p[9] == 17)
        .expect("a UDP reply on the wire");
    let (ip, payload) = Ipv4Header::parse(&reply).expect("parse reply");
    let (udp, body) = UdpHeader::parse(payload).expect("parse UDP");
    assert_eq!(ip.src, *RESOLVER.ip(), "the answer came from 8.8.8.8");
    assert_eq!(udp.src_port, 53);
    assert_eq!(udp.dst_port, CLIENT.port());
    assert_eq!(body, b"\x12\x34\x01\x00\x00\x01\x00\x00");
    assert!(
        verify_transport_v4(ip.src, ip.dst, IpProtocol::Udp, payload),
        "the restored reply carries a valid checksum"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_handshake_answer_returns_from_the_original_resolver() {
    let (backend, host) = hijacking_backend();
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = backend
        .spawn(device.duplicate().unwrap(), host.clone())
        .expect("spawn");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A TCP resolver connection starts with a SYN toward port 53.
    let script = Script::new(CLIENT, RESOLVER);
    let syn = script.tcp(1000, 0, 0x02, b"");
    device.push(&[&syn]);

    let answer = collect_written(&device, "the SYN-ACK on the wire")
        .into_iter()
        .find(|p| p.len() >= 40 && p[9] == 6)
        .expect("SYN-ACK");
    handle.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (ip, payload) = Ipv4Header::parse(&answer).expect("parse SYN-ACK");
    assert_eq!(ip.src, *RESOLVER.ip(), "the handshake came from 8.8.8.8");
    assert!(
        verify_transport_v4(ip.src, ip.dst, IpProtocol::Tcp, payload),
        "the restored SYN-ACK carries a valid checksum"
    );
}
