// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A device that goes away under the stack (an adapter disabled outside
//! the process) stops the stack with the reason on its handle, as
//! sing-tun's engine stops on a read error it cannot recover from; the
//! stack does not rebuild itself, and a stop the host asked for is never
//! reported as a loss.

#![cfg(any(feature = "backend-native", feature = "backend-ipstack"))]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vfawn_core::{
    Action, DeviceCaps, FlowInfo, IcmpPacket, PacketDevice, SessionHandler, StackBackend,
    StackHandle, TcpSession, UdpSession, Verdict,
};
use vfawn_testsuite::{MockDevice, Script};

struct Noop;

#[async_trait::async_trait]
impl SessionHandler for Noop {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }
    async fn on_tcp(&self, _session: TcpSession) {}
    async fn on_udp(&self, _session: UdpSession) {}
    async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
        Action::Drop
    }
}

fn failure_within(handle: &StackHandle, limit: Duration) -> Option<String> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(reason) = handle.failure() {
            return Some(reason);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

fn the_lost_device_stops_the_stack(backend: Box<dyn StackBackend>) {
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = backend
        .spawn(device.duplicate().unwrap(), Arc::new(Noop))
        .expect("spawn");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(handle.failure(), None, "a running stack reports nothing");

    device.lose();
    let reason = failure_within(&handle, Duration::from_secs(3)).expect("the loss is reported");
    assert!(reason.contains("device is down"), "{reason}");
    assert!(handle.is_stopped(), "the stack stopped rather than retried");
}

/// A dying device can refuse its writer before its reader fails (N-13
/// of the Windows retest: the CLI hung after "device write failed").
/// The refused write is dropped, as sing-tun's endpoint drops it; the
/// loss is still the reader's to report, with its reason, once the
/// read fails on the same dead device.
fn a_refused_write_leaves_the_loss_to_the_reader(backend: Box<dyn StackBackend>) {
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = backend
        .spawn(device.duplicate().unwrap(), Arc::new(Noop))
        .expect("spawn");
    std::thread::sleep(Duration::from_millis(100));

    device.lose_writes();
    let script = Script::new(
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443),
    );
    device.push(&[&script.tcp(1000, 0, 0x02, b"")]);
    let deadline = Instant::now() + Duration::from_secs(3);
    while device.refused_writes() == 0 {
        assert!(
            Instant::now() < deadline,
            "the SYN's answer was never written"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        failure_within(&handle, Duration::from_millis(200)),
        None,
        "a refused write alone is dropped, not a loss"
    );
    assert!(!handle.is_stopped());

    device.lose();
    let reason = failure_within(&handle, Duration::from_secs(3)).expect("the loss is reported");
    assert!(reason.contains("device is down"), "{reason}");
    assert!(handle.is_stopped());
}

fn an_asked_stop_is_not_a_loss(backend: Box<dyn StackBackend>) {
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = backend
        .spawn(device.duplicate().unwrap(), Arc::new(Noop))
        .expect("spawn");
    std::thread::sleep(Duration::from_millis(100));
    handle.stop();
    // The device leaving with the orderly stop is expected.
    device.lose();
    assert_eq!(failure_within(&handle, Duration::from_millis(300)), None);
}

#[cfg(feature = "backend-native")]
#[test]
fn native_stops_on_a_lost_device() {
    the_lost_device_stops_the_stack(Box::new(vfawn_stack_user::NativeBackend::default()));
}

#[cfg(feature = "backend-native")]
#[test]
fn native_reports_a_loss_its_writer_saw_first() {
    a_refused_write_leaves_the_loss_to_the_reader(Box::new(
        vfawn_stack_user::NativeBackend::default(),
    ));
}

#[cfg(feature = "backend-native")]
#[test]
fn native_orderly_stop_is_not_a_loss() {
    an_asked_stop_is_not_a_loss(Box::new(vfawn_stack_user::NativeBackend::default()));
}

#[cfg(feature = "backend-ipstack")]
#[test]
fn ipstack_stops_on_a_lost_device() {
    the_lost_device_stops_the_stack(Box::new(vfawn_stack_user::IpstackBackend::default()));
}

#[cfg(feature = "backend-ipstack")]
#[test]
fn ipstack_reports_a_loss_its_writer_saw_first() {
    a_refused_write_leaves_the_loss_to_the_reader(Box::new(
        vfawn_stack_user::IpstackBackend::default(),
    ));
}

#[cfg(feature = "backend-ipstack")]
#[test]
fn ipstack_orderly_stop_is_not_a_loss() {
    an_asked_stop_is_not_a_loss(Box::new(vfawn_stack_user::IpstackBackend::default()));
}
