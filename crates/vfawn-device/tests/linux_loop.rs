// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Round-trip tests against a real TUN device.
//!
//! These need root and a Linux kernel, so they carry `#[ignore]` and run
//! on demand or in CI with elevation:
//!
//! ```sh
//! sudo -E cargo test -p vfawn-device -- --ignored --nocapture
//! ```
//!
//! The read path is exercised by having the kernel generate traffic: an
//! on-link address makes `ping` route its probes straight into the device,
//! and every probe shows up as a read. The write path hands one of those
//! packets back to the kernel, which accepts it regardless of what it
//! contains afterwards.

#![cfg(target_os = "linux")]

use bytes::BytesMut;
use std::process::Command;
use std::thread;
use std::time::Duration;
use vfawn_core::{DeviceConfig, PacketDevice};
use vfawn_device::TunDevice;

fn loop_config() -> DeviceConfig {
    DeviceConfig {
        mtu: 1500,
        inet4_address: vec!["198.18.0.1/15".parse().unwrap()],
        ..DeviceConfig::default()
    }
}

#[test]
#[ignore]
fn reads_kernel_traffic_writes_back_and_stops_cleanly() {
    let mut device = TunDevice::create(&loop_config()).expect("create device");
    let caps = device.capabilities();
    assert_eq!(caps.queues, 1);
    assert!(!caps.gro && !caps.gso);

    let pinger = thread::spawn(|| {
        Command::new("ping")
            .args(["-c", "4", "-i", "0.2", "-W", "2", "198.18.0.2"])
            .output()
    });

    let mut seen = 0usize;
    let mut sample: Option<Vec<u8>> = None;
    let mut bufs = vec![BytesMut::new(); 8];
    while seen < 4 {
        let count = device.read_batch(&mut bufs).expect("read batch");
        if count == 0 {
            break;
        }
        for buf in bufs.iter().take(count) {
            // Every probe is an IPv4 ICMP echo request toward the on-link
            // address.
            assert_eq!(buf[0] >> 4, 4);
            assert_eq!(buf[9], 1);
            if sample.is_none() {
                sample = Some(buf.to_vec());
            }
            seen += 1;
        }
    }
    assert!(seen >= 4, "expected at least four probes, saw {seen}");

    let packet = sample.unwrap();
    let echoed = [BytesMut::from(&packet[..])];
    assert_eq!(device.write_batch(&echoed).unwrap(), 1);

    // Shutdown is idempotent; afterwards reads drain to zero and writes
    // are refused.
    device.shutdown().unwrap();
    device.shutdown().unwrap();
    let mut drained = vec![BytesMut::new(); 2];
    assert_eq!(device.read_batch(&mut drained).unwrap(), 0);
    assert!(device.write_batch(&[BytesMut::from(&packet[..])]).is_err());
    let _ = pinger.join().expect("ping thread");
}

#[test]
#[ignore]
fn shutdown_wakes_a_blocked_reader_from_another_thread() {
    let mut device = TunDevice::create(&loop_config()).expect("create device");
    let handle = device.shutdown_handle();
    let reader = thread::spawn(move || {
        let mut bufs = vec![BytesMut::new(); 4];
        device.read_batch(&mut bufs)
    });
    thread::sleep(Duration::from_millis(300));
    handle.shutdown().expect("shutdown via handle");
    assert_eq!(reader.join().unwrap().unwrap(), 0);
}

#[test]
#[ignore]
fn duplicate_name_is_refused() {
    let first = DeviceConfig {
        name: Some("vfawntest0".into()),
        ..loop_config()
    };
    let second = DeviceConfig {
        name: Some("vfawntest0".into()),
        ..loop_config()
    };

    let one = TunDevice::create(&first).expect("first create");
    assert!(TunDevice::create(&second).is_err());
    drop(one);
}
