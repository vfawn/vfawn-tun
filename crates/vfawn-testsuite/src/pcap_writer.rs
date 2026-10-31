// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A `PacketDevice` wrapper that records every packet to a sink, for
//! capturing what a stack sends in response to a replay.
//!
//! The sink is a callback, not a file handle, so the same wrapper serves
//! on-screen debugging, pcap file writing, and in-memory assertion. Each
//! observation carries the direction, so a test can tell requests from
//! responses apart.

use bytes::BytesMut;
use std::io;
use std::sync::Arc;
use vfawn_core::{DeviceCaps, PacketDevice};

/// Which way a captured packet was moving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Arriving from the device into the stack.
    Read,
    /// Leaving the stack toward the device.
    Write,
}

/// Receives every packet and its direction.
pub type Sink = Arc<dyn Fn(&[u8], Direction) + Send + Sync>;

/// Wraps a device and mirrors every packet to a sink.
pub struct PcapWriter {
    inner: Box<dyn PacketDevice>,
    sink: Sink,
}

impl PcapWriter {
    pub fn new(inner: Box<dyn PacketDevice>, sink: Sink) -> Self {
        Self { inner, sink }
    }
}

impl PacketDevice for PcapWriter {
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        let count = self.inner.read_batch(bufs)?;
        for buf in bufs.iter().take(count) {
            (self.sink)(buf, Direction::Read);
        }
        Ok(count)
    }

    fn write_batch(&mut self, bufs: &[BytesMut]) -> io::Result<usize> {
        for buf in bufs {
            (self.sink)(buf, Direction::Write);
        }
        self.inner.write_batch(bufs)
    }

    fn capabilities(&self) -> DeviceCaps {
        self.inner.capabilities()
    }

    fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown()
    }

    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "wrap the inner duplicate in a new PcapWriter instead",
        ))
    }
}
