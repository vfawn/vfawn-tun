// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Device-facing contract.
//!
//! A [`PacketDevice`] moves raw IP packets in batches. Batching is the core
//! abstraction: on every platform the first throughput ceiling of a
//! TUN-backed data path is the syscall rate, so the contract is batch-shaped
//! from the start even where the implementation fills batches one packet at
//! a time.

use bytes::BytesMut;
use std::io;

/// Read and write capability facts reported by a device.
///
/// These describe what the device actually supports, not what was
/// requested. An adopted fd (VPN service, network extension) has no offload
/// and must report it as such rather than let callers assume it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceCaps {
    /// Segmentation offload on the write path (Linux vnet headers).
    pub gso: bool,
    /// Coalescing offload on the read path (Linux vnet headers).
    pub gro: bool,
    /// Number of hardware queues. One on every platform except Linux with
    /// multi-queue enabled.
    pub queues: usize,
}

impl DeviceCaps {
    /// Single queue, no offload: the floor every code path must handle.
    pub const MINIMAL: DeviceCaps = DeviceCaps {
        gso: false,
        gro: false,
        queues: 1,
    };
}

/// Batched raw-packet I/O against a TUN-style device.
pub trait PacketDevice: Send {
    /// Fill `bufs` with as many pending packets as fit and return the count.
    /// Blocks when nothing is pending. After [`PacketDevice::shutdown`] a
    /// read returns `Ok(0)` and never blocks, so data-plane loops can treat
    /// zero as their exit condition.
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize>;

    /// Write as many whole packets as the device accepts in one call and
    /// return the count. Buffers are not resized by the callee.
    fn write_batch(&mut self, bufs: &[BytesMut]) -> io::Result<usize>;

    /// What the device supports right now.
    fn capabilities(&self) -> DeviceCaps;

    /// Wake any blocked reader. Idempotent; safe to call from another
    /// thread while a read is in flight.
    fn shutdown(&self) -> io::Result<()>;
}
