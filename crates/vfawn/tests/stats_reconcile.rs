// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The instance's session accounting, reconciled against the wire: a
//! scripted session exchanges known byte counts through the native
//! stack, and the instance's shared tracker — attached exactly as
//! [`vfawn::stats::StatsHandler`] attaches it — must report the same
//! three numbers the host's own tracker hears. This is the pipe
//! [`crate::instance::StatsSnapshot`] reads; equal numbers here mean
//! the snapshot is the sessions' own account, not an estimate.

#![cfg(feature = "backend-native")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vfawn::stats::{InstanceTracker, StatsHandler};
use vfawn_core::{
    CloseReason, DeviceCaps, FlowInfo, FlowTrackerHook, PacketDevice, SessionHandler, StackBackend,
    TcpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::{MockDevice, Script};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);
const PAYLOAD: &[u8] = b"count me through both trackers, please";

/// The host's own accounting, the second opinion the reconciliation
/// compares against.
#[derive(Default)]
struct HostScales {
    established: AtomicU64,
    forward: AtomicU64,
    reverse: AtomicU64,
}

impl FlowTrackerHook for HostScales {
    fn count_forward(&self, n: u64) {
        self.forward.fetch_add(n, Ordering::Relaxed);
    }
    fn count_reverse(&self, n: u64) {
        self.reverse.fetch_add(n, Ordering::Relaxed);
    }
    fn established(&self) {
        self.established.fetch_add(1, Ordering::Relaxed);
    }
    fn closed(&self, _reason: CloseReason) {}
}

struct EchoOnce(Arc<HostScales>);

#[async_trait::async_trait]
impl SessionHandler for EchoOnce {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::AcceptWith {
            udp_timeout: None,
            tracker: Some(Arc::clone(&self.0) as Arc<dyn FlowTrackerHook>),
        }
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        let mut buffer = [0u8; 4096];
        if let Ok(n) = session.read(&mut buffer).await
            && n > 0
        {
            let _ = session.write(&buffer[..n]).await;
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
fn the_instance_tracker_matches_the_hosts_own_scales() {
    let host_scales = Arc::new(HostScales::default());
    let instance_tracker = Arc::new(InstanceTracker::new());

    // The exact composition an Instance runs: the host handler under
    // the counting wrapper.
    let handler = Arc::new(StatsHandler::new(
        Arc::new(EchoOnce(Arc::clone(&host_scales))),
        Arc::clone(&instance_tracker),
    ));

    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler)
        .expect("spawn native backend");

    let script = Script::new(CLIENT, SERVER);

    // Handshake.
    device.push(&[&script.tcp(1000, 0, 0x02, b"")]);
    let mut server_seq = 0;
    wait_for(
        || {
            let written = device.take_written();
            written
                .into_iter()
                .find(|p| p.len() >= 40 && p[9] == 6 && p[33] & 0x12 == 0x12)
                .map(|synack| {
                    server_seq =
                        u32::from_be_bytes([synack[24], synack[25], synack[26], synack[27]]);
                })
                .is_some()
        },
        "SYN-ACK",
    );
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x10, b"")]);

    // Data in, echo out.
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x18, PAYLOAD)]);
    wait_for(
        || {
            device
                .take_written()
                .iter()
                .any(|p| p.len() > 40 && p[9] == 6 && &p[40..] == PAYLOAD)
        },
        "echoed payload",
    );

    // Both trackers must settle on the same three numbers: one
    // established session, the payload forward, the echo reverse.
    wait_for(
        || {
            let (established, forward, reverse) = instance_tracker.snapshot();
            established == 1 && forward == PAYLOAD.len() as u64 && reverse == PAYLOAD.len() as u64
        },
        "the instance's numbers",
    );
    let (established, forward, reverse) = instance_tracker.snapshot();
    assert_eq!(host_scales.established.load(Ordering::Relaxed), established);
    assert_eq!(host_scales.forward.load(Ordering::Relaxed), forward);
    assert_eq!(host_scales.reverse.load(Ordering::Relaxed), reverse);
    assert_eq!(forward, PAYLOAD.len() as u64, "the payload, forward");
    assert_eq!(reverse, PAYLOAD.len() as u64, "the echo, reverse");
}
