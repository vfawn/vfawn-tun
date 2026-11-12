// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Android and iOS: the device belongs to the host.
//!
//! A VpnService (Android) or an NEPacketTunnelProvider (iOS) creates the
//! interface, owns its addresses and routes, and hands this process one
//! descriptor; the process never opens a device of its own, because the
//! platform grants that to the VPN framework alone. One reader thread
//! parks in the kernel and one writer thread drains a bounded channel —
//! the same split the desktop devices run — without offload: neither
//! platform exposes virtio headers on a descriptor it hands out.
//!
//! Framing is bare IP on both targets. Android's descriptor is raw IP
//! already; the iOS utun descriptor carries a four-byte family prefix
//! that tun-rs strips on read and stamps on write, so frames above this
//! file look the same everywhere.

use std::collections::VecDeque;
use std::io;
use std::io::ErrorKind;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::Duration;

use bytes::BytesMut;
use tun_rs::{InterruptEvent, SyncDevice};
use vfawn_core::{DeviceCaps, DeviceConfig, PacketDevice};

use crate::read_queue::{self, Backlog, Delivery};

/// The largest frame the reader accepts. The descriptor's MTU is the
/// host's to choose and not readable through an adopted fd on either
/// platform, so the scratch covers the IP ceiling and each frame leaves
/// with exactly its own length.
const FRAME_CEILING: usize = 65535;

/// Channel depths, matching the desktop devices: depth is the
/// backpressure between the threads and the stack above.
const READ_DEPTH: usize = 1024;
const WRITE_DEPTH: usize = 1024;

/// How long the writer's receive waits before re-checking the stop
/// flag.
const POLL: Duration = Duration::from_millis(50);

/// Consecutive read failures tolerated before the descriptor counts as
/// gone. A revoked VPN (the user toggled it off, another app took the
/// slot) leaves a descriptor that fails every read; without a cap the
/// reader would spin on it forever.
const READ_FAILURE_LIMIT: u32 = 64;

/// Everything the handles share with the two threads.
struct Shared {
    reads: SyncSender<Vec<BytesMut>>,
    writes: SyncSender<Vec<BytesMut>>,
    event: InterruptEvent,
    stopped: AtomicBool,
    backlog: Backlog,
}

impl Shared {
    /// Stop both threads: the event ends the reader's park in the
    /// kernel, the backlog wake ends a held frame's park.
    fn stop(&self) -> io::Result<()> {
        self.stopped.store(true, Ordering::Release);
        self.backlog.wake();
        self.event.trigger()
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}

/// One end of the host's device: the reader's half by construction, the
/// writer's half through [`PacketDevice::duplicate`].
pub struct TunDevice {
    shared: Arc<Shared>,
    reads: Option<Receiver<Vec<BytesMut>>>,
    /// Frames the caller's buffer could not take in one call; the next
    /// call serves these first.
    leftover: VecDeque<BytesMut>,
}

/// A detached shutdown control for a device owned by another thread.
pub struct ShutdownHandle {
    shared: Arc<Shared>,
}

impl ShutdownHandle {
    /// Request shutdown and wake the reader. Idempotent.
    pub fn shutdown(&self) -> io::Result<()> {
        self.shared.stop()
    }
}

impl TunDevice {
    /// Creation is the VPN framework's, never this process's.
    pub fn create(_config: &DeviceConfig) -> io::Result<Self> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "the device belongs to the host on this platform; pass its descriptor in device.file_descriptor",
        ))
    }

    /// The host named the interface and owns everything addressed by
    /// that name; nothing in this process routes by it.
    pub fn name(&self) -> io::Result<String> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "the interface name belongs to the host on this platform",
        ))
    }

    /// Adopt the descriptor the VPN framework handed to the host.
    ///
    /// # Safety
    ///
    /// The caller guarantees a valid, open TUN descriptor that nothing
    /// else reads or closes: Android's `ParcelFileDescriptor` must be
    /// detached (`detachFd`), and the iOS descriptor must stay owned by
    /// the packet-tunnel provider's process. Adoption consumes the fd.
    #[expect(unsafe_code)]
    pub unsafe fn from_fd(fd: RawFd) -> io::Result<Self> {
        // SAFETY: the contract above is the caller's to uphold; the call
        // only wraps the descriptor, it dereferences nothing else.
        let device = unsafe { SyncDevice::from_fd(fd) }?;
        // Interruptible reads only answer the stop signal promptly on a
        // nonblocking descriptor; Android hands out blocking ones by
        // default (VpnService.Builder.setBlocking).
        device.set_nonblocking(true)?;
        Self::spawn_io(device)
    }

    /// A handle through which another thread can stop the device.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    fn spawn_io(device: SyncDevice) -> io::Result<Self> {
        let (read_tx, read_rx) = mpsc::sync_channel(READ_DEPTH);
        let (write_tx, write_rx) = mpsc::sync_channel(WRITE_DEPTH);
        let shared = Arc::new(Shared {
            reads: read_tx,
            writes: write_tx,
            event: InterruptEvent::new()?,
            stopped: AtomicBool::new(false),
            backlog: Backlog::default(),
        });
        let device = Arc::new(device);
        let writer_shared = Arc::clone(&shared);
        let writer_device = Arc::clone(&device);
        thread::Builder::new()
            .name("vfawn-tun-writer".into())
            .spawn(move || write_loop(&writer_shared, &writer_device, &write_rx))?;
        let reader_shared = Arc::clone(&shared);
        thread::Builder::new()
            .name("vfawn-tun-io".into())
            .spawn(move || read_loop(&reader_shared, &device))?;
        Ok(TunDevice {
            shared,
            reads: Some(read_rx),
            leftover: VecDeque::new(),
        })
    }
}

/// The reader: park until the descriptor is readable or the stop event
/// fires, then hand the frame up by value. A full channel holds the
/// frame and reads nothing more until the reader makes room, so the
/// backlog stays in the kernel's queue as on the desktop devices
/// (read_queue.rs says why).
fn read_loop(shared: &Shared, device: &SyncDevice) {
    shared.backlog.register();
    let mut scratch = vec![0u8; FRAME_CEILING];
    let mut failures = 0u32;
    let mut held: Option<Vec<BytesMut>> = None;
    while !shared.is_stopped() {
        if let Some(frames) = held.take() {
            match shared.backlog.deliver(&shared.reads, frames) {
                Delivery::Sent => {}
                Delivery::Held(frames) => {
                    held = Some(frames);
                    shared.backlog.wait();
                    continue;
                }
                Delivery::Gone => return,
            }
        }
        match device.recv_intr(&mut scratch, &shared.event) {
            Ok(0) => {}
            Ok(len) => {
                failures = 0;
                let Some(frame) = scratch.get(..len) else {
                    continue;
                };
                match shared
                    .backlog
                    .deliver(&shared.reads, vec![BytesMut::from(frame)])
                {
                    Delivery::Sent => {}
                    Delivery::Held(frames) => held = Some(frames),
                    Delivery::Gone => return,
                }
            }
            // The event fires only for shutdown; the loop head sees the
            // flag and leaves.
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => {
                failures = failures.saturating_add(1);
                if failures >= READ_FAILURE_LIMIT {
                    eprintln!("vfawn: tun I/O stopped: descriptor keeps failing ({error})");
                    shared.stopped.store(true, Ordering::Release);
                    return;
                }
            }
        }
    }
}

/// The writer: the write channel's one consumer. Frames the pooled
/// emitter built carry a zeroed virtio headroom that no device here
/// wants; its first zero byte names it (no IP packet starts with zero).
fn write_loop(shared: &Shared, device: &SyncDevice, writes: &Receiver<Vec<BytesMut>>) {
    let mut refused = 0u64;
    loop {
        // A stop still writes what was accepted before it: those
        // batches were queued before the flag, so once the flag is
        // seen the queue is drained without waiting and the loop
        // leaves on the first empty look (the stack's last resets ride
        // exactly those batches).
        let stopping = shared.is_stopped();
        let batch = match writes.recv_timeout(if stopping { Duration::ZERO } else { POLL }) {
            Ok(batch) => batch,
            Err(mpsc::RecvTimeoutError::Timeout) if stopping => return,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        for frame in &batch {
            let head = usize::from(frame.first() == Some(&0)) * vfawn_wire::VNET_HEADROOM;
            let Some(packet) = frame.get(head..).filter(|packet| !packet.is_empty()) else {
                continue;
            };
            // The shutdown event interrupts every wait once it fires,
            // so the stop's drain writes without one: the descriptor
            // is nonblocking, and a full queue loses the frame below.
            let sent = if stopping {
                device.send(packet)
            } else {
                device.send_intr(packet, &shared.event)
            };
            match sent {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::Interrupted => return,
                Err(error) => {
                    // A full queue loses this frame, not the interface:
                    // TCP above retransmits, UDP loses one datagram.
                    refused = refused.wrapping_add(1);
                    if refused == 1 || refused.is_multiple_of(10_000) {
                        eprintln!("vfawn: tun write refused ({error}); refused {refused} frames");
                    }
                }
            }
        }
    }
}

impl PacketDevice for TunDevice {
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        let Some(reads) = &self.reads else {
            return Ok(0);
        };
        // A stopped device is gone, not idle, as on Windows: the reader
        // leaves and the stack reports the loss (a revoked VPN) instead
        // of polling a dead descriptor. An orderly stop answers the
        // same, and the stack, already stopping, records no loss.
        if self.shared.is_stopped() {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
        let served = read_queue::fill(reads, &mut self.leftover, bufs);
        if served > 0 {
            // Room was made: a frame the reader holds can go now.
            self.shared.backlog.wake();
        }
        Ok(served)
    }

    fn write_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        if self.shared.is_stopped() {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
        let batch: Vec<BytesMut> = bufs.iter_mut().map(std::mem::take).collect();
        let count = batch.len();
        if self.shared.writes.send(batch).is_err() {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
        Ok(count)
    }

    fn capabilities(&self) -> DeviceCaps {
        DeviceCaps::MINIMAL
    }

    fn shutdown(&self) -> io::Result<()> {
        self.shared.stop()
    }

    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        Ok(Box::new(TunDevice {
            shared: Arc::clone(&self.shared),
            reads: None,
            leftover: VecDeque::new(),
        }))
    }
}
