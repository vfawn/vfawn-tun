// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Smoke tests for the three test utilities: the fuzz injector corrupts
//! packets, the pcap writer records both directions, and the loopback
//! echoes writes back as reads.

use bytes::BytesMut;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use vfawn_core::{DeviceCaps, PacketDevice};
use vfawn_testsuite::{Direction, FuzzInjector, Loopback, MockDevice, PcapWriter};

#[test]
fn fuzz_injector_mutates_packets_on_read() {
    let mock = MockDevice::new(DeviceCaps::MINIMAL);
    mock.push(&[b"hello world"]);

    let mut injector = FuzzInjector::new(
        Box::new(mock),
        Arc::new(|data: &mut [u8]| {
            // Corrupt the first byte.
            if !data.is_empty() {
                data[0] ^= 0xFF;
            }
        }),
    );

    let mut bufs = vec![BytesMut::new(); 1];
    let count = injector.read_batch(&mut bufs).unwrap();
    assert_eq!(count, 1);
    assert_eq!(bufs[0][0], b'h' ^ 0xFF);
    assert_eq!(&bufs[0][1..], b"ello world");
}

#[test]
fn fuzz_injector_passes_writes_through() {
    let mock = MockDevice::new(DeviceCaps::MINIMAL);

    let mut injector = FuzzInjector::new(
        Box::new(mock),
        Arc::new(|data: &mut [u8]| {
            data[0] = 0xFF;
        }),
    );

    let outbound = [BytesMut::from(&b"outbound"[..])];
    assert_eq!(injector.write_batch(&outbound).unwrap(), 1);
    // Capabilities pass through the wrapper unchanged.
    assert_eq!(injector.capabilities(), DeviceCaps::MINIMAL);
}

#[test]
fn fuzz_injector_handles_malformed_packets_without_panicking() {
    let mock = MockDevice::new(DeviceCaps::MINIMAL);
    // Push a mix of valid and degenerate packets.
    mock.push(&[
        b"",
        &[0x45],
        &[0xFF; 2],
        &[0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6],
    ]);

    let mut injector = FuzzInjector::new(
        Box::new(mock),
        Arc::new(|data: &mut [u8]| {
            // Flip every bit; the stack under test must survive.
            for byte in data.iter_mut() {
                *byte ^= 0xAA;
            }
        }),
    );

    let mut bufs = vec![BytesMut::new(); 4];
    let count = injector.read_batch(&mut bufs).unwrap();
    assert_eq!(count, 4);
    // No panic; all four degenerate inputs came through mutated.
}

#[test]
fn pcap_writer_records_both_directions() {
    let mock = MockDevice::new(DeviceCaps::MINIMAL);
    mock.push(&[b"input"]);

    let reads = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let read_count = Arc::clone(&reads);
    let write_count = Arc::clone(&writes);

    let mut writer = PcapWriter::new(
        Box::new(mock),
        Arc::new(move |_data, direction| {
            match direction {
                Direction::Read => read_count.fetch_add(1, Ordering::SeqCst),
                Direction::Write => write_count.fetch_add(1, Ordering::SeqCst),
            };
        }),
    );

    let mut bufs = vec![BytesMut::new(); 1];
    assert_eq!(writer.read_batch(&mut bufs).unwrap(), 1);
    assert_eq!(
        writer.write_batch(&[BytesMut::from(&b"out"[..])]).unwrap(),
        1
    );

    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(writes.load(Ordering::SeqCst), 1);
}

#[test]
fn loopback_echoes_writes_back_as_reads() {
    let mut loopback = Loopback::new(DeviceCaps::MINIMAL);
    assert_eq!(loopback.depth(), 0);

    // Write a packet; it should come back as a read.
    let packets = [BytesMut::from(&b"round trip"[..])];
    assert_eq!(loopback.write_batch(&packets).unwrap(), 1);
    assert_eq!(loopback.depth(), 1);

    let mut bufs = vec![BytesMut::new(); 1];
    assert_eq!(loopback.read_batch(&mut bufs).unwrap(), 1);
    assert_eq!(&bufs[0][..], &b"round trip"[..]);
    assert_eq!(loopback.depth(), 0);
}

#[test]
fn loopback_supports_external_injection() {
    let mut loopback = Loopback::new(DeviceCaps::MINIMAL);
    loopback.inject(b"from peer");

    let mut bufs = vec![BytesMut::new(); 1];
    assert_eq!(loopback.read_batch(&mut bufs).unwrap(), 1);
    assert_eq!(&bufs[0][..], &b"from peer"[..]);
}
