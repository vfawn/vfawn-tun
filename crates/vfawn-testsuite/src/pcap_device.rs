// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A `PacketDevice` that replays a pcap capture and records everything
//! written back, so a test can assert on the exact packet sequence a stack
//! produces for a given input.
//!
//! The input side is deterministic by construction: packets come out in
//! capture order, one per `read_batch` slot, with no timing dependence.
//! The output side collects whole packets in write order. Assertions go
//! against packet semantics (parsed flags, sequence numbers), not raw
//! bytes, which keeps them readable and resistant to header-field noise.
//!
//! For the transitional ipstack backend, which runs on a real clock, time
//! assertions carry a tolerance; the virtual clock interface lets the
//! in-house stack make them exact.

use bytes::BytesMut;
use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use vfawn_core::{DeviceCaps, PacketDevice};

/// A device that plays back a pcap file.
pub struct PcapDevice {
    packets: Vec<Vec<u8>>,
    next: AtomicU64,
    written: Mutex<Vec<Vec<u8>>>,
    caps: DeviceCaps,
    shutdown: Arc<AtomicBool>,
}

impl PcapDevice {
    /// Load every packet from a pcap file (classic or pcapng through the
    /// pcap-file crate's reader). The file must exist.
    pub fn from_file(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut reader =
            PcapReader::new(file).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut packets = Vec::new();
        while let Some(record) = reader.next_packet() {
            let record = record.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            packets.push(record.data.to_vec());
        }
        Ok(Self::from_packets(packets))
    }

    /// Build directly from in-memory packets; useful for tests that
    /// construct packets programmatically.
    pub fn from_packets(packets: Vec<Vec<u8>>) -> Self {
        Self {
            packets,
            next: AtomicU64::new(0),
            written: Mutex::new(Vec::new()),
            caps: DeviceCaps::MINIMAL,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Everything written since the last call, in write order.
    pub fn take_written(&self) -> Vec<Vec<u8>> {
        let mut sink = self.written.lock().unwrap();
        sink.drain(..).collect()
    }

    /// Peek at what has been written without consuming it.
    pub fn peek_written(&self) -> Vec<Vec<u8>> {
        self.written.lock().unwrap().clone()
    }

    /// How many packets remain to be read.
    pub fn remaining(&self) -> usize {
        self.packets
            .len()
            .saturating_sub(self.next.load(Ordering::Acquire) as usize)
    }
}

impl PacketDevice for PcapDevice {
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        if self.shutdown.load(Ordering::Acquire) {
            return Ok(0);
        }
        let mut count = 0;
        for slot in bufs.iter_mut() {
            let index = self.next.load(Ordering::Acquire) as usize;
            if index >= self.packets.len() {
                break;
            }
            *slot = BytesMut::from(&self.packets[index][..]);
            self.next.fetch_add(1, Ordering::AcqRel);
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
        let mut sink = self.written.lock().unwrap();
        for buf in bufs {
            sink.push(buf.to_vec());
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
        Ok(Box::new(PcapDevice {
            packets: self.packets.clone(),
            next: AtomicU64::new(self.next.load(Ordering::Acquire)),
            written: Mutex::new(Vec::new()),
            caps: self.caps,
            shutdown: Arc::clone(&self.shutdown),
        }))
    }
}
