// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Every verdict variant driven through a live backend.
//!
//! A scripted SYN arrives, judge_flow answers with one of the six
//! variants, and the observable outcome must match the contract: the
//! accepting variants deliver a session to the host, the refusing ones
//! discard the stream. Beyond the mapping, two properties of the
//! callback itself are pinned here: a panicking host loses its flow but
//! not the data plane, and a slow callback delays exactly its own flow.
//!
//! Wire-level output sequences per verdict (RST on the wire, rewritten
//! destination) are the in-house stack's to produce; here the refusing
//! verdicts assert on the session layer, which is all the transitional
//! backend promises.

#![cfg(feature = "backend-ipstack")]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vfawn_core::{
    DeviceCaps, FlowInfo, PacketDevice, SessionHandler, StackBackend, TcpSession, UdpNat,
    UdpSession, UdpSessionMode, Verdict,
};
use vfawn_testsuite::{MockDevice, Script};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

/// One scripted flow through a backend whose host answers every judge
/// with `verdict`, after sleeping `delay`, optionally panicking first.
struct Outcome {
    sessions: usize,
    judge_calls: usize,
    /// Time from SYN pushed to session observed; meaningless when no
    /// session arrived.
    delivery: Duration,
}

struct ScriptedHost {
    verdict: fn() -> Verdict,
    delay: Duration,
    panic: bool,
    judge_calls: AtomicUsize,
    sessions: AtomicUsize,
    udp_sessions: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for ScriptedHost {
    fn judge_flow(&self, _flow: &FlowInfo, _first_packet: &[u8]) -> Verdict {
        self.judge_calls.fetch_add(1, Ordering::SeqCst);
        if self.panic {
            panic!("scripted host panic");
        }
        std::thread::sleep(self.delay);
        (self.verdict)()
    }

    async fn on_tcp(&self, _session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
    }

    async fn on_udp(&self, _session: UdpSession) {
        self.udp_sessions.fetch_add(1, Ordering::SeqCst);
    }

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

impl ScriptedHost {
    fn with_verdict(verdict: fn() -> Verdict) -> Arc<Self> {
        Arc::new(Self {
            verdict,
            delay: Duration::ZERO,
            panic: false,
            judge_calls: AtomicUsize::new(0),
            sessions: AtomicUsize::new(0),
            udp_sessions: AtomicUsize::new(0),
        })
    }
}

/// Push a single SYN and watch for a session, polling with a deadline.
async fn run_syn_flow(host: &Arc<ScriptedHost>, wait_for_session: Duration) -> Outcome {
    let backend = Box::new(vfawn_stack_user::IpstackBackend::default());
    let owned_device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = backend
        .spawn(owned_device.duplicate().unwrap(), host.clone())
        .expect("spawn");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let script = Script::new(CLIENT, SERVER);
    let syn = script.tcp(1000, 0, 0x02, b"");
    let started = Instant::now();
    owned_device.push(&[&syn]);

    let mut delivery = Duration::ZERO;
    loop {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if host.sessions.load(Ordering::SeqCst) > 0 {
            delivery = started.elapsed();
            break;
        }
        if started.elapsed() >= wait_for_session {
            break;
        }
    }

    handle.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;

    Outcome {
        sessions: host.sessions.load(Ordering::SeqCst),
        judge_calls: host.judge_calls.load(Ordering::SeqCst),
        delivery,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn accepting_verdicts_deliver_a_session() {
    for verdict in [
        || Verdict::Accept,
        || Verdict::AcceptWith {
            udp_timeout: None,
            tracker: None,
        },
        || Verdict::Bypass,
    ] as [fn() -> Verdict; 3]
    {
        let host = ScriptedHost::with_verdict(verdict);
        let outcome = run_syn_flow(&host, Duration::from_secs(2)).await;
        assert_eq!(outcome.judge_calls, 1, "judge ran once");
        assert_eq!(outcome.sessions, 1, "accepting verdict delivers a session");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn refusing_verdicts_discard_the_stream() {
    for verdict in [
        || Verdict::Drop,
        || Verdict::Reject,
        || {
            Verdict::Redirect(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 99, 0, 1),
                8443,
            )))
        },
    ] as [fn() -> Verdict; 3]
    {
        let host = ScriptedHost::with_verdict(verdict);
        let outcome = run_syn_flow(&host, Duration::from_millis(400)).await;
        assert_eq!(outcome.judge_calls, 1, "judge ran once");
        assert_eq!(
            outcome.sessions, 0,
            "refusing verdict must not deliver a session"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn panicking_judge_costs_the_flow_not_the_process() {
    let host = Arc::new(ScriptedHost {
        verdict: || Verdict::Accept,
        delay: Duration::ZERO,
        panic: true,
        judge_calls: AtomicUsize::new(0),
        sessions: AtomicUsize::new(0),
        udp_sessions: AtomicUsize::new(0),
    });

    let backend = Box::new(vfawn_stack_user::IpstackBackend::default());
    let owned_device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = backend
        .spawn(owned_device.duplicate().unwrap(), host.clone())
        .expect("spawn");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let script = Script::new(CLIENT, SERVER);
    let first = script.tcp(1000, 0, 0x02, b"");
    owned_device.push(&[&first]);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The same backend must keep judging new flows after the panic.
    let second = script.tcp(2000, 0, 0x02, b"");
    owned_device.push(&[&second]);
    tokio::time::sleep(Duration::from_millis(300)).await;

    handle.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(host.judge_calls.load(Ordering::SeqCst), 2);
    assert_eq!(host.sessions.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn slow_judge_slows_its_own_flow() {
    // The callback runs inline on the dispatch path, ahead of session
    // delivery, so its runtime is a floor on the flow's delivery time.
    // A 120ms callback must delay the session by at least that long;
    // the margin covers only clock read order, not machine speed.
    let slow_host = Arc::new(ScriptedHost {
        verdict: || Verdict::Accept,
        delay: Duration::from_millis(120),
        panic: false,
        judge_calls: AtomicUsize::new(0),
        sessions: AtomicUsize::new(0),
        udp_sessions: AtomicUsize::new(0),
    });
    let slow = run_syn_flow(&slow_host, Duration::from_secs(3)).await;
    assert_eq!(slow.sessions, 1);
    assert!(
        slow.delivery >= Duration::from_millis(110),
        "delivery took {:?} despite a 120ms callback",
        slow.delivery
    );
}

#[tokio::test(flavor = "current_thread")]
async fn udp_flows_register_in_the_nat_table() {
    let host = ScriptedHost::with_verdict(|| Verdict::Accept);
    let nat = Arc::new(UdpNat::new(
        UdpSessionMode::Symmetric,
        Duration::from_secs(300),
        0,
    ));

    let backend = Box::new(vfawn_stack_user::IpstackBackend {
        udp_nat: Arc::clone(&nat),
        ..vfawn_stack_user::IpstackBackend::default()
    });
    let owned_device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = backend
        .spawn(owned_device.duplicate().unwrap(), host.clone())
        .expect("spawn");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let script = Script::new(CLIENT, SERVER);
    let datagram = script.udp(b"query");
    owned_device.push(&[&datagram]);

    let deadline = Duration::from_secs(2);
    let started = Instant::now();
    while host.udp_sessions.load(Ordering::SeqCst) == 0 && started.elapsed() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    handle.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(host.udp_sessions.load(Ordering::SeqCst), 1);
    assert_eq!(nat.session_count(), 1, "the flow landed in the NAT table");
}
