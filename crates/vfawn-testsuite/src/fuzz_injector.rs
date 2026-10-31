// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A `PacketDevice` wrapper that mutates packets in flight, for fuzzing
//! the stack's tolerance to hostile input.
//!
//! The mutator is a caller-supplied function that receives each packet's
//! bytes and may alter them in place. Typical mutators flip bits, truncate
//! headers, or zero out checksums; anything that keeps the buffer length
//! valid works. The injector itself does not panic: mutation errors are
//! the stack's problem, not the test harness's.

use bytes::BytesMut;
use std::io;
use std::sync::Arc;
use vfawn_core::{DeviceCaps, PacketDevice};

/// A packet mutator; receives the raw bytes, may modify in place.
pub type Mutator = Arc<dyn Fn(&mut [u8]) + Send + Sync>;

/// Wraps a device and mutates every packet in both directions.
pub struct FuzzInjector {
    inner: Box<dyn PacketDevice>,
    mutator: Mutator,
}

impl FuzzInjector {
    pub fn new(inner: Box<dyn PacketDevice>, mutator: Mutator) -> Self {
        Self { inner, mutator }
    }

    /// A no-op mutator, useful as a control in comparative tests.
    pub fn passthrough(inner: Box<dyn PacketDevice>) -> Self {
        Self::new(inner, Arc::new(|_| {}))
    }
}

impl PacketDevice for FuzzInjector {
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        let count = self.inner.read_batch(bufs)?;
        for buf in bufs.iter_mut().take(count) {
            (self.mutator)(buf);
        }
        Ok(count)
    }

    fn write_batch(&mut self, bufs: &[BytesMut]) -> io::Result<usize> {
        // Write passes through unmodified; the interesting fuzzing is on
        // the read side, where hostile packets arrive.
        self.inner.write_batch(bufs)
    }

    fn capabilities(&self) -> DeviceCaps {
        self.inner.capabilities()
    }

    fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown()
    }

    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        // Duplicating the injector would duplicate the mutator state; for
        // the test patterns that need a split device, wrap the duplicate
        // of the inner device in a new injector with the same mutator.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "wrap the inner duplicate in a new FuzzInjector instead",
        ))
    }
}
