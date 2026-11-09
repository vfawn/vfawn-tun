// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The ipstack backend as a guest: on the host's runtime, drained on
//! the host's schedule, refusing on the wire.
//!
//! A host that lends its runtime gets its sessions as tasks beside its
//! own, so the handler can share connection pools without crossing
//! runtimes; nothing then ends those tasks but the drain, which must
//! return the moment the set empties and abort what outlives the grace
//! window. Reject must reach the client as a reset, not as a handshake
//! followed by silence.

#![cfg(feature = "backend-ipstack")]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vfawn_core::{
    DeviceCaps, Drain, FlowInfo, PacketDevice, SessionHandler, StackBackend, StackHandle,
    TcpSession, UdpSession, Verdict,
};
use vfawn_testsuite::{MockDevice, Script};
use vfawn_wire::{Ipv4Header, Ipv6Header, TcpFlags, TcpHeader, V6Payload};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

struct Host {
    verdict: fn() -> Verdict,
    /// Park every session forever: only an abort ends it.
    hold: bool,
    judge_calls: AtomicUsize,
    sessions: AtomicUsize,
    session_threads: Mutex<Vec<String>>,
}

impl Host {
    fn new(verdict: fn() -> Verdict, hold: bool) -> Arc<Self> {
        Arc::new(Self {
            verdict,
            hold,
            judge_calls: AtomicUsize::new(0),
            sessions: AtomicUsize::new(0),
            session_threads: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl SessionHandler for Host {
    fn judge_flow(&self, _flow: &FlowInfo, _first_packet: &[u8]) -> Verdict {
        self.judge_calls.fetch_add(1, Ordering::SeqCst);
        (self.verdict)()
    }

    async fn on_tcp(&self, _session: TcpSession) {
        let name = std::thread::current().name().unwrap_or("").to_string();
        self.session_threads.lock().unwrap().push(name);
        self.sessions.fetch_add(1, Ordering::SeqCst);
        if self.hold {
            std::future::pending::<()>().await;
        }
    }

    async fn on_udp(&self, _session: UdpSession) {}

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

fn host_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("host-rt")
        .enable_all()
        .build()
        .unwrap()
}

fn spawn_on(
    runtime: Option<tokio::runtime::Handle>,
    host: &Arc<Host>,
) -> std::io::Result<(StackHandle, MockDevice)> {
    let backend = Box::new(vfawn_stack_user::IpstackBackend {
        runtime,
        ..vfawn_stack_user::IpstackBackend::default()
    });
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = backend.spawn(device.duplicate().unwrap(), host.clone())?;
    Ok((handle, device))
}

fn wait_for(what: &str, deadline: Duration, mut done: impl FnMut() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn sessions_run_on_the_lent_runtime() {
    let runtime = host_runtime();
    let host = Host::new(|| Verdict::Accept, false);
    let (handle, device) = spawn_on(Some(runtime.handle().clone()), &host).unwrap();

    let syn = Script::new(CLIENT, SERVER).tcp(1000, 0, 0x02, b"");
    device.push(&[&syn]);
    wait_for("the session", Duration::from_secs(3), || {
        host.sessions.load(Ordering::SeqCst) == 1
    });

    assert_eq!(host.judge_calls.load(Ordering::SeqCst), 1, "judged once");
    assert_eq!(
        host.session_threads.lock().unwrap().as_slice(),
        ["host-rt"],
        "the session ran on the host's workers"
    );
    handle.stop();
    assert_eq!(handle.drain(Duration::from_secs(3)), Drain::Idle);
}

#[tokio::test(flavor = "current_thread")]
async fn a_current_thread_runtime_is_refused() {
    let host = Host::new(|| Verdict::Accept, false);
    let refused = spawn_on(Some(tokio::runtime::Handle::current()), &host)
        .err()
        .expect("a current-thread runtime cannot host ipstack streams");
    assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn an_idle_drain_returns_at_once() {
    let runtime = host_runtime();
    let host = Host::new(|| Verdict::Accept, false);
    let (handle, _device) = spawn_on(Some(runtime.handle().clone()), &host).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    handle.stop();
    let started = Instant::now();
    assert_eq!(handle.drain(Duration::from_secs(5)), Drain::Idle);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "an empty set must not wait out the window ({:?})",
        started.elapsed()
    );
}

#[test]
fn a_session_outliving_the_window_is_aborted() {
    let runtime = host_runtime();
    let host = Host::new(|| Verdict::Accept, true);
    let (handle, device) = spawn_on(Some(runtime.handle().clone()), &host).unwrap();

    let syn = Script::new(CLIENT, SERVER).tcp(1000, 0, 0x02, b"");
    device.push(&[&syn]);
    wait_for("the parked session", Duration::from_secs(3), || {
        host.sessions.load(Ordering::SeqCst) == 1
    });

    handle.stop();
    let started = Instant::now();
    assert_eq!(handle.drain(Duration::from_millis(100)), Drain::Aborted(1));
    assert!(started.elapsed() < Duration::from_secs(2));
    // The abort really ended it: a second drain finds nothing live.
    assert_eq!(handle.drain(Duration::from_millis(10)), Drain::Idle);
}

/// The first frame written back that parses as a TCP segment.
fn written_reset(device: &MockDevice) -> Option<(TcpHeader, SocketAddr, SocketAddr)> {
    device
        .take_written()
        .iter()
        .find_map(|frame| tcp_segment(frame))
}

fn tcp_segment(frame: &[u8]) -> Option<(TcpHeader, SocketAddr, SocketAddr)> {
    let (src, dst, segment) = match frame.first()? >> 4 {
        4 => {
            let (ip, payload) = Ipv4Header::parse(frame).ok()?;
            (ip.src.into(), ip.dst.into(), payload)
        }
        _ => {
            let (ip, rest) = Ipv6Header::parse(frame).ok()?;
            let payload = V6Payload::walk(ip.next_header, rest).ok()?;
            (ip.src.into(), ip.dst.into(), payload.bytes)
        }
    };
    let (tcp, _) = TcpHeader::parse(segment).ok()?;
    Some((
        tcp,
        SocketAddr::new(src, tcp.src_port),
        SocketAddr::new(dst, tcp.dst_port),
    ))
}

fn assert_reject_resets(client: SocketAddr, server: SocketAddr) {
    let host = Host::new(|| Verdict::Reject, false);
    let (handle, device) = spawn_on(None, &host).unwrap();
    std::thread::sleep(Duration::from_millis(100));

    let syn = Script::new(client, server).tcp(1000, 0, 0x02, b"");
    device.push(&[&syn]);
    let mut reset = None;
    wait_for("the reset", Duration::from_secs(3), || {
        if reset.is_none() {
            reset = written_reset(&device);
        }
        reset.is_some()
    });
    let (tcp, src, dst) = reset.unwrap();

    // RFC 9293 §3.4 for a SYN without ACK: <SEQ=0><ACK=SEG.SEQ+1><RST,ACK>.
    assert!(tcp.flags.contains(TcpFlags::RST.union(TcpFlags::ACK)));
    assert!(
        !tcp.flags.contains(TcpFlags::SYN),
        "no handshake on a refused flow"
    );
    assert_eq!(tcp.seq, 0);
    assert_eq!(tcp.ack, 1001);
    assert_eq!(
        (src, dst),
        (server, client),
        "the reset answers from the server"
    );
    assert_eq!(host.judge_calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.sessions.load(Ordering::SeqCst), 0);
    handle.stop();
    assert_eq!(handle.drain(Duration::from_secs(3)), Drain::Idle);
}

#[test]
fn reject_answers_a_v4_syn_with_a_reset() {
    assert_reject_resets(SocketAddr::V4(CLIENT), SocketAddr::V4(SERVER));
}

#[test]
fn reject_answers_a_v6_syn_with_a_reset() {
    let client = SocketAddrV6::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 45678, 0, 0);
    let server = SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443, 0, 0);
    assert_reject_resets(SocketAddr::V6(client), SocketAddr::V6(server));
}
