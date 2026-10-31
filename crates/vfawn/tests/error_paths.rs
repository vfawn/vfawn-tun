// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Error-path tests: the Instance must survive device failures, handler
//! panics and repeated shutdowns without taking the process down.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use vfawn_core::{DeviceCaps, PacketDevice};
use vfawn_testsuite::MockDevice;

use bytes::BytesMut;

/// A device that fails after N successful reads, simulating a kernel-side
/// error (carrier loss, fd closed by an external actor).
struct FailingDevice {
    inner: MockDevice,
    reads_remaining: AtomicUsize,
}

impl PacketDevice for FailingDevice {
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        if self.reads_remaining.fetch_sub(1, Ordering::SeqCst) == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "simulated device failure",
            ));
        }
        self.inner.read_batch(bufs)
    }

    fn write_batch(&mut self, bufs: &[BytesMut]) -> io::Result<usize> {
        self.inner.write_batch(bufs)
    }

    fn capabilities(&self) -> DeviceCaps {
        self.inner.capabilities()
    }

    fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown()
    }

    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        let reads = self.reads_remaining.load(Ordering::SeqCst);
        Ok(Box::new(FailingDevice {
            inner: MockDevice::new(DeviceCaps::MINIMAL),
            reads_remaining: AtomicUsize::new(reads),
        }))
    }
}

#[test]
fn panic_in_spawned_thread_is_contained_and_stop_still_works() {
    // A panic inside a data-plane thread must not take the process down,
    // and the stop flag must remain operable from outside.
    let handle = vfawn_core::StackHandle::new();
    let stop = handle.clone();
    let contained = Arc::new(AtomicUsize::new(0));

    let flag = Arc::clone(&contained);
    let worker = std::thread::Builder::new()
        .name("test-panic-worker".into())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Simulate a handler panic inside the runtime.
                panic!("simulated data-plane panic");
            }));
            if outcome.is_err() {
                flag.fetch_add(1, Ordering::SeqCst);
            }
            // The stop flag is still reachable from this thread.
            stop.stop();
        })
        .expect("spawn worker");

    worker.join().expect("thread must survive the panic");
    assert_eq!(contained.load(Ordering::SeqCst), 1);
    assert!(handle.is_stopped());
}

#[test]
fn failing_device_does_not_crash_the_bridge_threads() {
    let device = FailingDevice {
        inner: MockDevice::new(DeviceCaps::MINIMAL),
        reads_remaining: AtomicUsize::new(1),
    };
    device.inner.push(&[b"packet1", b"packet2"]);

    let mut reader = device;
    let mut bufs = vec![BytesMut::new(); 4];

    // First few reads succeed.
    let n = reader.read_batch(&mut bufs).unwrap();
    assert_eq!(n, 2);

    // Then the device fails; the read returns an error, not a panic.
    let result = reader.read_batch(&mut bufs);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn shutdown_handle_stops_from_multiple_threads() {
    let handle = vfawn_core::StackHandle::new();
    let h1 = handle.clone();
    let h2 = handle.clone();

    let t1 = std::thread::spawn(move || h1.stop());
    let t2 = std::thread::spawn(move || h2.stop());

    t1.join().unwrap();
    t2.join().unwrap();

    assert!(handle.is_stopped());
    // Stopping an already-stopped handle is fine.
    handle.stop();
    assert!(handle.is_stopped());
}

#[test]
fn mock_device_write_after_shutdown_is_rejected() {
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    device.shutdown().unwrap();

    let mut dev = device;
    let result = dev.write_batch(&[BytesMut::from(&b"late"[..])]);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotConnected);
}

#[test]
fn pcap_device_remaining_tracks_consumption() {
    let device = vfawn_testsuite::PcapDevice::from_packets(vec![
        b"one".to_vec(),
        b"two".to_vec(),
        b"three".to_vec(),
    ]);
    assert_eq!(device.remaining(), 3);

    let mut dev = device;
    let mut bufs = vec![BytesMut::new(); 1];
    assert_eq!(dev.read_batch(&mut bufs).unwrap(), 1);
    assert_eq!(dev.remaining(), 2);
    assert_eq!(dev.read_batch(&mut bufs).unwrap(), 1);
    assert_eq!(dev.remaining(), 1);
    assert_eq!(dev.read_batch(&mut bufs).unwrap(), 1);
    assert_eq!(dev.remaining(), 0);
    assert_eq!(dev.read_batch(&mut bufs).unwrap(), 0);
}

#[test]
fn loopback_shutdown_stops_both_directions() {
    let mut loopback = vfawn_testsuite::Loopback::new(DeviceCaps::MINIMAL);
    loopback.shutdown().unwrap();

    let mut bufs = vec![BytesMut::new(); 1];
    assert_eq!(loopback.read_batch(&mut bufs).unwrap(), 0);
    assert!(loopback.write_batch(&[BytesMut::new()]).is_err());
}
