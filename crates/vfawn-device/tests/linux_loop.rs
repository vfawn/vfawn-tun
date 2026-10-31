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
use std::time::{Duration, Instant};
use vfawn_core::{DeviceConfig, PacketDevice};
use vfawn_device::TunDevice;

/// Each test gets its own /24 so parallel kernel traffic for one device
/// never lands in another: the on-link route of the newest interface would
/// otherwise capture a sibling test's probes.
fn subnet_config(index: u8) -> DeviceConfig {
    DeviceConfig {
        mtu: 1500,
        inet4_address: vec![format!("198.18.{index}.1/24").parse().unwrap()],
        ..DeviceConfig::default()
    }
}

#[test]
#[ignore]
fn reads_kernel_traffic_writes_back_and_stops_cleanly() {
    let mut device = TunDevice::create(&subnet_config(0)).expect("create device");
    let caps = device.capabilities();
    assert_eq!(caps.queues, 1);
    assert!(!caps.gro && !caps.gso);

    let pinger = thread::spawn(|| {
        Command::new("ping")
            .args(["-c", "4", "-i", "0.2", "-W", "2", "198.18.0.2"])
            .output()
    });

    // Count only echo probes; a shared runner emits unrelated traffic into
    // any captured prefix, and the read path should pass it through
    // untouched rather than the test caring what it is.
    let mut seen = 0usize;
    let mut sample: Option<Vec<u8>> = None;
    let mut bufs = vec![BytesMut::new(); 8];
    let deadline = Instant::now() + Duration::from_secs(10);
    while seen < 4 && Instant::now() < deadline {
        let count = device.read_batch(&mut bufs).expect("read batch");
        if count == 0 {
            break;
        }
        for buf in bufs.iter().take(count) {
            if buf.len() >= 10 && buf[0] >> 4 == 4 && buf[9] == 1 {
                if sample.is_none() {
                    sample = Some(buf.to_vec());
                }
                seen += 1;
            }
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
    // Nothing generates traffic for this prefix, so the reader stays parked
    // inside the kernel until the interrupt arrives.
    let mut device = TunDevice::create(&subnet_config(1)).expect("create device");
    let handle = device.shutdown_handle();
    // A freshly brought-up interface receives kernel housekeeping (IPv6
    // router solicitations, MLD reports) before it goes quiet, so the
    // reader keeps reading until the interrupt lands; that it returns at
    // all is the proof the wake works, and the drain must end in zero.
    let reader = thread::spawn(move || {
        let mut bufs = vec![BytesMut::new(); 4];
        let mut noise = 0usize;
        loop {
            match device.read_batch(&mut bufs) {
                Ok(0) => break Ok(noise),
                Ok(count) => noise += count,
                Err(error) => break Err(error),
            }
        }
    });
    thread::sleep(Duration::from_millis(300));
    handle.shutdown().expect("shutdown via handle");
    let noise = reader.join().unwrap().unwrap();
    assert!(noise < 8, "unexpected traffic flood: {noise} packets");
}

#[test]
#[ignore]
fn duplicate_name_is_refused() {
    let first = DeviceConfig {
        name: Some("vfawntest0".into()),
        ..subnet_config(2)
    };
    let second = DeviceConfig {
        name: Some("vfawntest0".into()),
        ..subnet_config(2)
    };

    let one = TunDevice::create(&first).expect("first create");
    assert!(TunDevice::create(&second).is_err());
    drop(one);
}
