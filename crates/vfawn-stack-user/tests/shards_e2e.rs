// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The shard skeleton exercised end to end: packets from a mock device
//! through the producer's hash split, a shard's connection table, an
//! echo slot, and back out to the device. Affinity (one flow, one
//! shard) and the steady-state allocation budget (established flows
//! move packets without allocating) are the two properties the whole
//! M3 story stands on.

#![cfg(feature = "backend-native")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use vfawn_core::{DeviceCaps, PacketDevice};
use vfawn_stack_user::{ShardConfig, Shards, UdpEcho};
use vfawn_testsuite::{MockDevice, Script};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45000);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 7000);

fn start(count: usize) -> (Shards, MockDevice) {
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let read_half = device.duplicate().unwrap();
    let shards = Shards::start(
        read_half,
        device.duplicate().unwrap(),
        ShardConfig {
            shards: count,
            mtu: 1500,
            ..ShardConfig::default()
        },
        std::sync::Arc::new(|_| Box::new(UdpEcho)),
    );
    (shards, device)
}

fn wait_for_written(device: &MockDevice, minimum: usize) -> Vec<Vec<u8>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let written = device.take_written();
        if written.len() >= minimum || std::time::Instant::now() > deadline {
            return written;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn udp_echo_traverses_every_hop() {
    let (shards, device) = start(4);
    let script = Script::new(CLIENT, SERVER);
    let payload = b"through the bed";
    let packet = script.udp(payload);
    device.push(&[&packet]);

    let written = wait_for_written(&device, 1);
    shards.stop();
    drop(shards);

    assert_eq!(written.len(), 1, "one packet in, one echoed back");
    let reply = &written[0];
    // Endpoints swapped, payload intact.
    assert_eq!(&reply[12..16], SERVER.ip().octets());
    assert_eq!(&reply[16..20], CLIENT.ip().octets());
    let body = &reply[28..];
    assert_eq!(body, payload);
}

#[test]
fn one_flow_lands_on_exactly_one_shard() {
    let (shards, device) = start(4);
    let script = Script::new(CLIENT, SERVER);
    for _ in 0..32 {
        device.push(&[&script.udp(b"affinity")]);
        std::thread::sleep(Duration::from_millis(2));
    }
    wait_for_written(&device, 32);
    shards.stop();
    let busy: Vec<u64> = shards
        .processed
        .iter()
        .map(|counter| counter.load(Ordering::Relaxed))
        .collect();
    let touched = busy.iter().filter(|count| **count > 0).count();
    assert_eq!(
        touched, 1,
        "a single five-tuple must stay on one shard, saw {busy:?}"
    );
}

#[test]
fn many_flows_reach_many_shards() {
    let (shards, device) = start(4);
    // Distinct source ports: deterministic hash spreads them.
    for port in 40000u16..40032 {
        let client = SocketAddrV4::new(*CLIENT.ip(), port);
        let script = Script::new(client, SERVER);
        device.push(&[&script.udp(b"spread")]);
        std::thread::sleep(Duration::from_millis(2));
    }
    wait_for_written(&device, 32);
    shards.stop();
    let busy: Vec<u64> = shards
        .processed
        .iter()
        .map(|counter| counter.load(Ordering::Relaxed))
        .collect();
    let touched = busy.iter().filter(|count| **count > 0).count();
    assert!(
        touched >= 2,
        "32 flows must not pile onto one shard: {busy:?}"
    );
}

// The allocation budget probe: with established slots and a warmed
// pool, moving packets through the skeleton must not allocate. The
// counter is process-global; the test runs one shard to keep the
// measurement honest about which thread allocates.
static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// The probe wraps the system allocator; the fourth sanctioned unsafe
// site, test-only, counting is a plain pass-through otherwise.
struct Counting;

#[expect(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn steady_state_moves_packets_without_allocating() {
    let (shards, device) = start(1);
    let script = Script::new(CLIENT, SERVER);

    // Establish the slot and warm every pool.
    device.push(&[&script.udp(b"warm")]);
    let warmed = wait_for_written(&device, 1);
    assert_eq!(warmed.len(), 1);

    // Thread plumbing ticks (sleeps, timers) cost a few allocations a
    // second regardless of traffic; the honest question is the marginal
    // cost of one packet. Two equal windows, one idle and one carrying
    // the packet, cancel the tick noise.
    fn measure(window: Duration) -> u64 {
        COUNTING.store(true, Ordering::SeqCst);
        ALLOCATIONS.store(0, Ordering::SeqCst);
        std::thread::sleep(window);
        let count = ALLOCATIONS.load(Ordering::SeqCst);
        COUNTING.store(false, Ordering::SeqCst);
        count
    }

    let baseline = measure(Duration::from_millis(300));
    device.push(&[&script.udp(b"steady state payload")]);
    let with_packet = measure(Duration::from_millis(300));
    let echoed = device.take_written();
    shards.stop();

    assert_eq!(echoed.len(), 1, "the steady packet came back");
    let marginal = with_packet.saturating_sub(baseline);
    assert!(
        marginal <= 4,
        "one steady-state packet cost {marginal} allocations (idle baseline {baseline}, with traffic {with_packet}); the young skeleton budget is 4, the 037 goal is 0"
    );
}
