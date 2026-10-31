// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! An in-memory `PacketDevice` for tests and replay.
//!
//! Packets pushed before a read are handed out in order; everything written
//! lands in a sink the test inspects. There is no blocking: an empty inbox
//! returns zero, which mirrors the post-shutdown contract of real devices
//! closely enough for deterministic loops. Duplicates share the queues and
//! the shutdown signal, so a reader and a writer see the same device.

use bytes::BytesMut;
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use vfawn_core::{DeviceCaps, PacketDevice};

pub struct MockDevice {
    inbox: Arc<Mutex<VecDeque<BytesMut>>>,
    outbox: Arc<Mutex<VecDeque<BytesMut>>>,
    caps: DeviceCaps,
    shutdown: Arc<AtomicBool>,
}

impl MockDevice {
    /// A device reporting the given capabilities and no pending packets.
    pub fn new(caps: DeviceCaps) -> Self {
        Self {
            inbox: Arc::new(Mutex::new(VecDeque::new())),
            outbox: Arc::new(Mutex::new(VecDeque::new())),
            caps,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Queue packets for the next reads, in order.
    pub fn push(&self, packets: &[&[u8]]) {
        let mut inbox = self.inbox.lock().unwrap();
        for packet in packets {
            inbox.push_back(BytesMut::from(&packet[..]));
        }
    }

    /// Everything written since the last call, in write order.
    pub fn take_written(&self) -> Vec<Vec<u8>> {
        let mut outbox = self.outbox.lock().unwrap();
        outbox.drain(..).map(|b| b.to_vec()).collect()
    }

    /// Packets still waiting to be read.
    pub fn pending(&self) -> usize {
        self.inbox.lock().unwrap().len()
    }
}

impl PacketDevice for MockDevice {
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        if self.shutdown.load(Ordering::Acquire) {
            return Ok(0);
        }
        let mut inbox = self.inbox.lock().unwrap();
        let mut count = 0;
        for slot in bufs.iter_mut() {
            let Some(packet) = inbox.pop_front() else {
                break;
            };
            *slot = packet;
            count += 1;
        }
        Ok(count)
    }

    fn write_batch(&mut self, bufs: &[BytesMut]) -> io::Result<usize> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "device is down",
            ));
        }
        let mut outbox = self.outbox.lock().unwrap();
        for packet in bufs {
            outbox.push_back(packet.clone());
        }
        Ok(bufs.len())
    }

    fn capabilities(&self) -> DeviceCaps {
        self.caps
    }

    fn shutdown(&self) -> io::Result<()> {
        self.shutdown.store(true, Ordering::Release);
        Ok(())
    }

    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        Ok(Box::new(MockDevice {
            inbox: Arc::clone(&self.inbox),
            outbox: Arc::clone(&self.outbox),
            caps: self.caps,
            shutdown: Arc::clone(&self.shutdown),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn reads_return_queued_packets_in_order() {
        let mut device = MockDevice::new(DeviceCaps::MINIMAL);
        device.push(&[b"one", b"two", b"three"]);
        let mut bufs = vec![BytesMut::new(); 2];
        assert_eq!(device.read_batch(&mut bufs).unwrap(), 2);
        assert_eq!(bufs[0], &b"one"[..]);
        assert_eq!(bufs[1], &b"two"[..]);
        assert_eq!(device.pending(), 1);
    }

    #[test]
    fn empty_reads_report_zero_without_blocking() {
        let mut device = MockDevice::new(DeviceCaps::MINIMAL);
        let mut bufs = vec![BytesMut::new(); 4];
        assert_eq!(device.read_batch(&mut bufs).unwrap(), 0);
    }

    #[test]
    fn writes_land_in_the_sink_in_order() {
        let mut device = MockDevice::new(DeviceCaps::MINIMAL);
        let first = BytesMut::from(&b"alpha"[..]);
        let second = BytesMut::from(&b"beta"[..]);
        assert_eq!(device.write_batch(&[first, second]).unwrap(), 2);
        assert_eq!(
            device.take_written(),
            vec![b"alpha".to_vec(), b"beta".to_vec()]
        );
        assert!(device.take_written().is_empty());
    }

    #[test]
    fn shutdown_flips_read_and_write_semantics() {
        let mut device = MockDevice::new(DeviceCaps::MINIMAL);
        device.push(&[b"late"]);
        device.shutdown().unwrap();
        device.shutdown().unwrap();
        let mut bufs = vec![BytesMut::new(); 1];
        assert_eq!(device.read_batch(&mut bufs).unwrap(), 0);
        let error = device.write_batch(&[BytesMut::new()]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotConnected);
    }

    #[test]
    fn capabilities_report_what_was_constructed() {
        let caps = DeviceCaps {
            gso: true,
            gro: true,
            queues: 4,
        };
        let device = MockDevice::new(caps);
        assert_eq!(device.capabilities(), caps);
    }

    #[test]
    fn duplicates_share_queues_and_shutdown() {
        let mut reader = MockDevice::new(DeviceCaps::MINIMAL);
        let mut writer = MockDevice::new(DeviceCaps::MINIMAL);
        // Share the queues by constructing a duplicate directly, avoiding
        // the downcast round-trip that Box<dyn PacketDevice> would need.
        writer.inbox = Arc::clone(&reader.inbox);
        writer.outbox = Arc::clone(&reader.outbox);
        writer.shutdown = Arc::clone(&reader.shutdown);

        // The writer sees packets the reader queues.
        reader.push(&[b"through"]);
        let mut bufs = vec![BytesMut::new(); 1];
        assert_eq!(reader.read_batch(&mut bufs).unwrap(), 1);
        assert_eq!(bufs[0], &b"through"[..]);

        // The reader sees what the duplicate writes.
        let outbound = [BytesMut::from(&b"back"[..])];
        writer.write_batch(&outbound).unwrap();
        assert_eq!(reader.take_written(), vec![b"back".to_vec()]);

        // Shutdown on either side reaches both.
        writer.shutdown().unwrap();
        let mut bufs = vec![BytesMut::new(); 1];
        assert_eq!(reader.read_batch(&mut bufs).unwrap(), 0);
    }
}
