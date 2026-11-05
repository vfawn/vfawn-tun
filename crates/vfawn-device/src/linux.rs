// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Linux TUN device on top of tun-rs.
//!
//! One queue, one I/O thread. The thread owns the descriptor and turns
//! both directions into channels: reads arrive as owned frame batches,
//! writes leave as batches the thread stages and hands to the kernel in
//! one call when the offload path is on. The split-half model above
//! this file (a reader blocking in the kernel, a writer with its own
//! descriptor) cannot carry vnet headers: duplicating shares a queue
//! the library refuses to adopt twice, and cloning into a second queue
//! lets the kernel steer inbound packets to the half that never reads.
//! A thread that owns both directions has neither problem.

use std::io;
use std::io::ErrorKind;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread;

use bytes::BytesMut;
use tun_rs::{DeviceBuilder, InterruptEvent, SyncDevice, VIRTIO_NET_HDR_LEN};
use vfawn_core::{DeviceCaps, DeviceConfig, PacketDevice};

/// Frame budget when the configuration leaves the MTU to the platform.
/// Large frames keep the syscall rate down; the kernel never reads past
/// the end of an actual packet, so the slack costs address space only.
const DEFAULT_MTU: u32 = 65535;

/// How many read batches may wait for the reader, and how many write
/// batches may wait for the I/O thread, before the sending side blocks:
/// the pipeline's backpressure is the channel depth.
const READ_DEPTH: usize = 1024;
const WRITE_DEPTH: usize = 1024;

/// Frames handed between the I/O thread and a caller in one batch:
/// the library's own ideal, because a merged GRO burst under bulk load
/// arrives as many segments at once and a short buffer array turns
/// that into a fatal "too many GSO segments".
const BATCH: usize = tun_rs::IDEAL_BATCH_SIZE;

/// The MTU in force for buffer sizing, after platform derivation.
fn effective_mtu(explicit: u32) -> u32 {
    if explicit == 0 { DEFAULT_MTU } else { explicit }
}

/// Everything the handles share with the I/O thread.
struct Shared {
    reads: SyncSender<Vec<BytesMut>>,
    writes: SyncSender<Vec<BytesMut>>,
    event: InterruptEvent,
    stopped: AtomicBool,
    /// The read-side fast dispatch, installed once at stack spawn: a
    /// claimed packet never enters the read channel. The lock is taken
    /// once per read batch, not per packet, and is otherwise
    /// uncontended.
    dispatch: Mutex<Option<vfawn_core::device::ReadDispatch>>,
}

/// One end of the device: the reader's half by construction, the
/// writer's half through [`PacketDevice::duplicate`], which shares the
/// same I/O thread and channels instead of touching the descriptor.
pub struct TunDevice {
    shared: Arc<Shared>,
    reads: Option<Receiver<Vec<BytesMut>>>,
    caps: DeviceCaps,
    name: Option<String>,
}

/// A detached shutdown control for a device owned by another thread.
///
/// The data-plane loop owns the device; signal handlers and management
/// code hold this handle instead.
pub struct ShutdownHandle {
    shared: Arc<Shared>,
}

impl ShutdownHandle {
    /// Request shutdown and wake the I/O thread. Idempotent.
    pub fn shutdown(&self) -> io::Result<()> {
        self.shared.stopped.store(true, Ordering::Release);
        self.shared.event.trigger()
    }
}

impl TunDevice {
    /// Create and bring up a device as described by `config`.
    ///
    /// The interface receives the first configured IPv4 address and every
    /// configured IPv6 address. Additional IPv4 addresses are a routing
    /// concern, not a framing one, and land with the route engine.
    pub fn create(config: &DeviceConfig) -> io::Result<Self> {
        let mtu = effective_mtu(config.mtu);
        // Vnet stays off: with it the kernel coalesces the peer's
        // inbound TCP and both stacks above collapse (measured 4.5
        // Mbit/s on an eight-stream upload against 200 without it,
        // buffer sizing already corrected ,  the merged-burst semantics
        // need dedicated integration work in the stacks, tracked as
        // its own item). The plain-frame path is the stable truth.
        let mut builder = DeviceBuilder::new().mtu(mtu as u16);
        if let Some(name) = &config.name {
            builder = builder.name(name.clone());
        }
        if let Some(net) = config.inet4_address.first() {
            builder = builder.ipv4(net.addr(), net.prefix_len(), None);
        }
        for net in &config.inet6_address {
            builder = builder.ipv6(net.addr(), net.prefix_len());
        }
        let device = builder.build_sync()?;
        let caps = DeviceCaps::MINIMAL;
        Self::spawn_io(device, caps)
    }

    /// The interface name the kernel knows this device by.
    ///
    /// Route orchestration needs the real name: with no configured name
    /// the driver assigns one, and rules and addresses must reference
    /// exactly that.
    pub fn name(&self) -> io::Result<String> {
        Ok(self.name.clone().unwrap_or_else(|| "tun0".to_string()))
    }

    /// Adopt a device fd supplied by the host, as VPN services and network
    /// extensions do. An adopted fd carries no offload by nature, so the
    /// capability floor applies regardless of what created it.
    ///
    /// # Safety
    ///
    /// The caller guarantees the framing contract: a valid, open TUN fd
    /// framed without packet information and without vnet headers, and not
    /// owned by anyone else. Adoption consumes the fd.
    // fd adoption is one of the sanctioned unsafe spots; the budget stays
    // at one and each site carries its reasoning inline.
    #[expect(unsafe_code)]
    pub unsafe fn from_fd(fd: RawFd) -> io::Result<Self> {
        // SAFETY: the contract above is the caller's to uphold; the call
        // only wraps the fd, it dereferences nothing else.
        let device = unsafe { SyncDevice::from_fd(fd) }?;
        let caps = DeviceCaps::MINIMAL;
        Self::spawn_io(device, caps)
    }

    /// A handle through which another thread can stop the device.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    fn spawn_io(device: SyncDevice, caps: DeviceCaps) -> io::Result<Self> {
        let name = device.name()?;
        let (read_tx, read_rx) = mpsc::sync_channel(READ_DEPTH);
        let (write_tx, write_rx) = mpsc::sync_channel(WRITE_DEPTH);
        let event = InterruptEvent::new()?;
        let shared = Arc::new(Shared {
            reads: read_tx,
            writes: write_tx,
            event,
            stopped: AtomicBool::new(false),
            dispatch: Mutex::new(None),
        });
        let io_shared = Arc::clone(&shared);
        thread::Builder::new()
            .name("vfawn-tun-io".into())
            .spawn(move || io_loop(io_shared, device, write_rx))?;
        Ok(TunDevice {
            shared,
            reads: Some(read_rx),
            caps,
            name: Some(name),
        })
    }
}

/// The I/O thread: one descriptor, two directions, one loop.
///
/// Writes drain first (a batch already waiting is worth more than one
/// more poll), then the kernel read blocks until a frame, the poll
/// budget, or a wake arrives; a wake is either a write enqueue or the
/// stop flag, which the loop head sorts.
fn io_loop(shared: Arc<Shared>, mut device: SyncDevice, writes: Receiver<Vec<BytesMut>>) {
    let mut drop_counter = 0u64;
    let mut sizes = vec![0usize; BATCH];
    // The buffers the kernel read fills hold one split segment each
    // (the merged burst lands whole in the scratch above and the
    // library slices it out), so an MTU-plus-slack length is the
    // whole requirement ,  sizing them to the merge ceiling instead
    // zeroed megabytes per cycle and crushed an offload run to
    // single-digit Mbit/s. They travel to the reader by ownership;
    // the reader's empties flow back and get topped up (free inside
    // capacity).
    let seg = 1514;
    let mut bufs: Vec<BytesMut> = (0..BATCH).map(|_| BytesMut::zeroed(seg)).collect();
    let mut gro_table = tun_rs::GROTable::default();
    let mut staging: Vec<BytesMut> = Vec::new();
    let mut original = vec![0u8; VIRTIO_NET_HDR_LEN + 65535];

    loop {
        for buf in bufs.iter_mut() {
            if buf.len() < seg {
                buf.resize(seg, 0);
            }
        }
        loop {
            match writes.try_recv() {
                Ok(batch) => {
                    if let Err(error) =
                        send_batch(&mut device, &mut gro_table, &mut staging, &batch)
                    {
                        // A queue that cannot take the batch right now
                        // is backpressure, not death: the drop behaves
                        // like a qdisc drop (TCP above retransmits,
                        // UDP loses one datagram), which beats taking
                        // the whole interface down mid-transfer ,  the
                        // kernel removes the device with the last fd,
                        // and every route falls through to a bypass.
                        if error.kind() == ErrorKind::NotConnected {
                            eprintln!("vfawn: tun I/O stopped: device down");
                            shared.stopped.store(true, Ordering::Release);
                            return;
                        }
                        drop_counter = drop_counter.wrapping_add(1);
                        if drop_counter == 1 || drop_counter.is_multiple_of(10_000) {
                            eprintln!(
                                "vfawn: tun write refused ({error}); dropped {drop_counter} batches"
                            );
                        }
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    eprintln!("vfawn: tun I/O stopped: writers gone");
                    return;
                }
            }
        }
        if shared.stopped.load(Ordering::Acquire) {
            return;
        }
        match device.recv_multiple_intr(&mut original, &mut bufs, &mut sizes, 0, &shared.event) {
            Ok(count) if count > 0 => {
                // The fast dispatch first: a claimed packet is answered
                // here — payload out through the claim, answer frames
                // staged for this loop's own write path — and its
                // buffer stays in rotation (no take, no
                // channel, no re-zeroing). What declines rides the
                // read channel exactly as before.
                let dispatch = shared.dispatch.lock().expect("dispatch").clone();
                let mut frames = Vec::with_capacity(count);
                let mut answers: Vec<BytesMut> = Vec::new();
                match &dispatch {
                    Some(dispatch) => {
                        for buf in bufs.iter_mut().take(count) {
                            if (dispatch.claim)(&buf[..], &mut answers) {
                                continue;
                            }
                            frames.push(std::mem::take(buf));
                        }
                        // The batch's end: whatever the claims
                        // accumulated for their own sockets leaves
                        // now, before the answers do.
                        (dispatch.finish)();
                    }
                    None => {
                        for buf in bufs.iter_mut().take(count) {
                            frames.push(std::mem::take(buf));
                        }
                    }
                }
                // The staged answers leave the same way the write
                // channel's batches do — one send per read batch, on
                // this thread, with no queue between. A send failure
                // is qdisc-shaped loss (the peer's loss recovery
                // re-asks and the slot answers); only the device's
                // death stops the loop.
                if !answers.is_empty()
                    && let Err(error) =
                        send_batch(&mut device, &mut gro_table, &mut staging, &answers)
                    && error.kind() == ErrorKind::NotConnected
                {
                    eprintln!("vfawn: tun I/O stopped: device down");
                    shared.stopped.store(true, Ordering::Release);
                    return;
                }
                if frames.is_empty() {
                    continue;
                }
                // A full read channel drops the batch (a qdisc-shaped
                // loss: TCP retransmits, UDP loses one datagram).
                // Blocking here would freeze the device: the single
                // I/O thread is the only reader AND the only writer,
                // so a blocked send stalls both directions, which is
                // the intermittent whole-pipeline death the multi-
                // round bench kept hitting.
                match shared.reads.try_send(frames) {
                    Ok(()) => {}
                    Err(std::sync::mpsc::TrySendError::Full(_dropped)) => {}
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                        eprintln!("vfawn: tun I/O stopped: reader gone");
                        return;
                    }
                }
            }
            Ok(_) => {}
            // The wake is the write side's knock or the stop flag's.
            // The event is level-triggered: it stays high until reset,
            // so an unreset wake turns this loop into a spin that
            // starves every reader. Reset first, then loop: the head
            // drains whatever writes exist, and one landing later
            // re-triggers the (now clear) event.
            Err(error) if error.kind() == ErrorKind::Interrupted => {
                let _ = shared.event.reset();
                continue;
            }
            Err(error) if error.kind() == ErrorKind::NotConnected => {
                eprintln!("vfawn: tun I/O stopped: device down");
                shared.stopped.store(true, Ordering::Release);
                return;
            }
            // Any other read failure ,  a burst that still does not fit,
            // a hiccup in the merge path ,  loses that one read, not the
            // interface: the kernel retries, the flows retransmit, and
            // the descriptor staying alive keeps the routes owning the
            // namespace.
            Err(error) => {
                eprintln!("vfawn: tun read failed ({error}); continuing");
            }
        }
    }
}

/// One write batch onto the wire: staged into header-padded frames and
/// handed over in a single kernel call on the offload path, one send
/// per frame otherwise.
fn send_batch(
    device: &mut SyncDevice,
    gro_table: &mut tun_rs::GROTable,
    staging: &mut Vec<BytesMut>,
    batch: &[BytesMut],
) -> io::Result<()> {
    for frame in batch {
        let mut padded = BytesMut::with_capacity(VIRTIO_NET_HDR_LEN + frame.len());
        padded.resize(VIRTIO_NET_HDR_LEN, 0);
        padded.extend_from_slice(frame);
        staging.push(padded);
    }
    device.send_multiple(gro_table, staging, VIRTIO_NET_HDR_LEN)?;
    staging.clear();
    Ok(())
}

impl PacketDevice for TunDevice {
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        let Some(reads) = &self.reads else {
            return Ok(0);
        };
        if self.shared.stopped.load(Ordering::Acquire) {
            return Ok(0);
        }
        // The old contract returns zero when nothing arrived, and
        // callers loop on it; an unbounded block here would hang every
        // poll-style reader past its own deadline.
        let mut frames = match reads.recv_timeout(std::time::Duration::from_millis(50)) {
            Ok(frames) => frames,
            Err(_) => return Ok(0),
        };
        // Ownership swaps, bytes never copy: the caller's buffers join
        // the circulating pool by leaving here inside its frames.
        let count = frames.len().min(bufs.len());
        for (slot, frame) in bufs.iter_mut().zip(frames.iter_mut()).take(count) {
            std::mem::swap(slot, frame);
        }
        Ok(count)
    }

    fn write_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
        let batch: Vec<BytesMut> = bufs.iter_mut().map(std::mem::take).collect();
        let count = batch.len();
        // Channel depth is the backpressure; the wake makes the I/O
        // thread see the batch now rather than at the poll budget.
        if self.shared.writes.send(batch).is_err() {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
        self.shared.event.trigger()?;
        Ok(count)
    }

    fn capabilities(&self) -> DeviceCaps {
        self.caps
    }

    fn shutdown(&self) -> io::Result<()> {
        ShutdownHandle {
            shared: Arc::clone(&self.shared),
        }
        .shutdown()
    }

    // Not a second queue: a handle to the same I/O thread, carrying
    // only the write direction. The read side stays with the original,
    // which is exactly the split the pipeline above expects.
    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        Ok(Box::new(TunDevice {
            shared: Arc::clone(&self.shared),
            reads: None,
            caps: self.caps,
            name: self.name.clone(),
        }))
    }

    fn set_read_dispatch(&self, dispatch: vfawn_core::device::ReadDispatch) {
        *self.shared.dispatch.lock().expect("dispatch") = Some(dispatch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_mtu_selects_the_platform_default() {
        assert_eq!(effective_mtu(0), DEFAULT_MTU);
        assert_eq!(effective_mtu(1500), 1500);
    }
}
