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
use std::sync::Arc;

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

/// A read-side fast-path claim the device's owner installs: true
/// takes the packet out of the read path entirely, and any frames the
/// claim produced (its answer traffic) append to the second argument —
/// the device's own I/O loop sends them with its write path, so the
/// claim never touches a queue or a thread it does not own.
pub type ReadDispatch = Arc<dyn Fn(&[u8], &mut Vec<BytesMut>) -> bool + Send + Sync>;

/// Batched raw-packet I/O against a TUN-style device.
///
/// The framing contract is raw IP, version 4 or 6, with no
/// link-layer header: Linux TUN hands that over as-is, Windows
/// wintun likewise, and Darwin's utun strips or adds its address
/// family prefix in its own implementation. Every consumer above
/// this trait is platform-free by construction.
pub trait PacketDevice: Send {
    /// Fill `bufs` with as many pending packets as fit and return the count.
    /// Blocks when nothing is pending. After [`PacketDevice::shutdown`] a
    /// read returns `Ok(0)` and never blocks, so data-plane loops can treat
    /// zero as their exit condition.
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize>;

    /// Write as many whole packets as the device accepts in one call and
    /// return the count. Buffers are not resized by the callee.
    fn write_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize>;

    /// What the device supports right now.
    fn capabilities(&self) -> DeviceCaps;

    /// Wake any blocked reader. Idempotent; safe to call from another
    /// thread while a read is in flight.
    fn shutdown(&self) -> io::Result<()>;

    /// Produce a second handle to the same underlying device, so one thread
    /// can block in [`PacketDevice::read_batch`] while another writes.
    ///
    /// The duplicate shares the shutdown signal: stopping either handle
    /// wakes both. On a real device this is a duplicate of the file
    /// descriptor; on in-memory devices it is a clone of the queues.
    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>>;

    /// Install a per-packet read-side dispatch that the device's owner
    /// runs before frames enter the read path. Returning true claims
    /// the packet entirely — it never reaches
    /// [`PacketDevice::read_batch`] — and any answer frames it
    /// produced leave through the device's own write path. The
    /// default installs nothing, so reads deliver everything; the
    /// claim is a device-side fast path, never a filter the stack
    /// above may rely on for correctness.
    fn set_read_dispatch(&self, _dispatch: ReadDispatch) {}
}
