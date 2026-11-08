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

/// The read-side fast path a stack installs in the device's I/O loop.
///
/// `claim` runs per packet, before anything enters the read path:
/// true takes the packet out of it entirely, and any answer frames it
/// produced (its ACK traffic) append to the second argument. `finish`
/// runs once at the end of each read batch — the one point a claiming
/// side may batch what it accumulated (one outbound write per socket,
/// for instance), because no further claim arrives before it. Both
/// run on the I/O loop's thread, so the pair may share staging state
/// without locks against each other.
/// The sink a device feeds write buffers to after the kernel has
/// taken their bytes.
pub type FrameRelease = std::sync::Arc<dyn Fn(&mut Vec<bytes::BytesMut>) + Send + Sync>;

#[derive(Clone)]
pub struct ReadDispatch {
    pub claim: ClaimFn,
    pub finish: FinishFn,
}

/// One packet's claim: true takes it out of the read path.
pub type ClaimFn = Arc<dyn Fn(&[u8], &mut Vec<BytesMut>) -> bool + Send + Sync>;
/// The read batch's end: whatever the claims accumulated leaves now.
pub type FinishFn = Arc<dyn Fn() + Send + Sync>;

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

    /// Install the sink for write buffers once the kernel has their
    /// bytes. A device whose write path is asynchronous (frames cross
    /// a channel to a writer thread) feeds the whole batch here after
    /// its syscalls instead of dropping it, so a pooled emitter's
    /// circulation closes. The default drops — honest for devices
    /// that write synchronously.
    fn set_write_release(&self, _release: FrameRelease) {}
}
