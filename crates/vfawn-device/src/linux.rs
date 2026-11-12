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

use std::collections::VecDeque;
use std::io;
use std::io::ErrorKind;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;

use bytes::BytesMut;
use tun_rs::{DeviceBuilder, InterruptEvent, SyncDevice, VIRTIO_NET_HDR_LEN};
use vfawn_core::{DeviceCaps, DeviceConfig, PacketDevice};

use crate::read_queue::{self, Backlog, Delivery};

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
    backlog: Backlog,
    /// The read-side fast dispatch, installed once at stack spawn: a
    /// claimed packet never enters the read channel. The lock is taken
    /// once per read batch, not per packet, and is otherwise
    /// uncontended.
    dispatch: Mutex<Option<vfawn_core::device::ReadDispatch>>,
    /// The sink for write buffers after their syscall: the pooled
    /// emitter's circulation closes here, or the default drop stands
    /// in when no pool owns the frames.
    release: Mutex<Option<vfawn_core::device::FrameRelease>>,
}

/// One end of the device: the reader's half by construction, the
/// writer's half through [`PacketDevice::duplicate`], which shares the
/// same I/O thread and channels instead of touching the descriptor.
pub struct TunDevice {
    shared: Arc<Shared>,
    reads: Option<Receiver<Vec<BytesMut>>>,
    /// The tail of a batch wider than the caller's buffers: a merged
    /// GRO burst splits into up to [`BATCH`] frames, more than a
    /// caller asks for at once.
    leftover: VecDeque<BytesMut>,
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
        self.shared.backlog.wake();
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
        // Vnet is the Linux acceleration: the kernel merges the
        // peer's inbound segments on the read side (the reader's
        // per-packet cost collapses) and the write side's merged
        // frames ride the TSO fast path (measured together: the
        // upload holds seven and a half gigabits across eight flows
        // against two without, the download keeps its two and a
        // quarter, the kernel's transmit queue stops dropping, and
        // the per-frame header staging is the price the writer
        // thread — five percent of a core at saturation — pays).
        // The plain-frame path stays one environment switch away: it
        // is the floor every platform without virtio headers runs
        // on, and the escape hatch when a kernel's offload misbe-
        // haves. The transmit queue is the burst shock absorber: the
        // peer's kernel pumps eight streams at line rate and the
        // reader drains in batches — a shallow queue (the library's
        // 1000 default) overflowed at every burst seam, and the
        // kernel dropped whole segments before the process ever saw
        // them (nine thousand drops and a hundred sixty thousand
        // retransmissions inside ten seconds, measured).
        let offload = std::env::var_os("VFAWN_NO_OFFLOAD").is_none();
        let mut builder = DeviceBuilder::new()
            .mtu(mtu as u16)
            .tx_queue_len(10_000)
            .offload(offload);
        if let Some(name) = &config.name {
            builder = builder.name(name.clone());
        }
        if let Some(net) = &config.inet4_address.first() {
            builder = builder.ipv4(net.addr(), net.prefix_len(), None);
        }
        for net in &config.inet6_address {
            builder = builder.ipv6(net.addr(), net.prefix_len());
        }
        let device = builder.build_sync()?;
        let caps = if offload {
            DeviceCaps {
                gso: true,
                gro: true,
                queues: 1,
            }
        } else {
            DeviceCaps::MINIMAL
        };
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
        if !caps.gro {
            // TSO off when vnet is off: the kernel's TCP
            // segmentation offload buffers MSS-sized frames for a
            // merge the vnet-less writes can never describe, holding
            // each until its timer expires. With vnet on, the merged
            // write frames are exactly what TSO exists to segment.
            let _ = std::process::Command::new("ethtool")
                .args(["-K", &name, "tso", "off"])
                .output();
        }
        let (read_tx, read_rx) = mpsc::sync_channel(READ_DEPTH);
        let (write_tx, write_rx) = mpsc::sync_channel(WRITE_DEPTH);
        let event = InterruptEvent::new()?;
        let shared = Arc::new(Shared {
            reads: read_tx,
            writes: write_tx,
            event,
            stopped: AtomicBool::new(false),
            backlog: Backlog::default(),
            dispatch: Mutex::new(None),
            release: Mutex::new(None),
        });
        // The descriptor is full duplex: reads and writes are
        // independent halves of the tun socket, so the write side
        // earns its own thread on its own handle. One thread doing
        // both saturated at the downlink's two gigabits (the peer's
        // acknowledgments then queued behind the unread side until
        // the kernel's tun queue overflowed — tun0 tx_dropped — and
        // every dropped acknowledgment became a retransmission
        // cascade), and no amount of interleaving fairness fixes a
        // core that is simply full.
        let device = Arc::new(SharedTun(device));
        let writer_shared = Arc::clone(&shared);
        let writer_device = Arc::clone(&device);
        thread::Builder::new()
            .name("vfawn-tun-writer".into())
            .spawn(move || write_loop(writer_shared, writer_device, write_rx, caps.gso))?;
        let io_shared = Arc::clone(&shared);
        let reader_device = Arc::clone(&device);
        thread::Builder::new()
            .name("vfawn-tun-io".into())
            .spawn(move || io_loop(io_shared, reader_device, caps.gso))?;
        Ok(TunDevice {
            shared,
            reads: Some(read_rx),
            leftover: VecDeque::new(),
            caps,
            name: Some(name),
        })
    }
}

/// The device shared by the reader and writer threads. The tun file
/// is full duplex and its read and write syscalls are independent;
/// every method used here takes the device by shared reference and is
/// a stateless call on the descriptor.
struct SharedTun(SyncDevice);
// SAFETY: the kernel serializes file operations on the same
// descriptor; the two threads issue disjoint halves (read vs write)
// of a stateless full-dupplex socket, and none of the methods called
// through this wrapper mutate shared Rust-side state.
#[expect(unsafe_code)]
unsafe impl Sync for SharedTun {}

/// The reader half of the device: the kernel read blocks until a
/// frame, the poll budget, or a wake arrives (a wake is the stop
/// flag's), the fast dispatch claims what it can, and the answers it
/// produced leave inline on this thread's own write — the turnaround
/// a claimed payload's acknowledgment owes the peer is one syscall,
/// not a channel crossing. Everything else a caller wrote travels the
/// write channel to the writer thread.
fn io_loop(shared: Arc<Shared>, device: Arc<SharedTun>, vnet: bool) {
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
    let mut original = vec![0u8; VIRTIO_NET_HDR_LEN + 65535];
    shared.backlog.register();
    // A batch the read channel had no room for: while it waits nothing
    // more is read, and the backlog stays in the kernel's tun queue
    // (read_queue.rs says why).
    let mut held: Option<Vec<BytesMut>> = None;

    loop {
        for buf in bufs.iter_mut() {
            if buf.len() < seg {
                buf.resize(seg, 0);
            }
        }
        if shared.stopped.load(Ordering::Acquire) {
            return;
        }
        if let Some(frames) = held.take() {
            match shared.backlog.deliver(&shared.reads, frames) {
                Delivery::Sent => {}
                Delivery::Held(frames) => {
                    held = Some(frames);
                    shared.backlog.wait();
                    continue;
                }
                Delivery::Gone => {
                    eprintln!("vfawn: tun I/O stopped: reader gone");
                    return;
                }
            }
        }
        match device
            .0
            .recv_multiple_intr(&mut original, &mut bufs, &mut sizes, 0, &shared.event)
        {
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
                    && let Err(error) = send_batch(&device.0, vnet, &mut answers, &mut Vec::new())
                    && error.kind() == ErrorKind::NotConnected
                {
                    eprintln!("vfawn: tun I/O stopped: device down");
                    shared.stopped.store(true, Ordering::Release);
                    return;
                }
                if frames.is_empty() {
                    continue;
                }
                // A full read channel holds the batch rather than drop
                // it. Not a blocking send: that would sleep through
                // the stop flag, and the park the hold takes wakes on
                // it as on the reader's room.
                match shared.backlog.deliver(&shared.reads, frames) {
                    Delivery::Sent => {}
                    Delivery::Held(frames) => held = Some(frames),
                    Delivery::Gone => {
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

/// The writer half of the device: the write channel's one consumer.
/// A batch arriving wakes it directly (the channel's own blocking
/// receive — no event fd, no polling), a full queue is the
/// backpressure senders wait on, and a refused write is backpressure
/// or death by the same rules the read half lives by.
fn write_loop(
    shared: Arc<Shared>,
    device: Arc<SharedTun>,
    writes: Receiver<Vec<BytesMut>>,
    vnet: bool,
) {
    let mut drop_counter = 0u64;
    // One scratch for the whole thread: the offload path's per-frame
    // prefix staging once allocated a buffer per frame — a hundred
    // seventy thousand allocations a second at the downlink's peak,
    // all on the thread that was saturating. The scratch grows to the
    // frame ceiling once and the allocator never hears from this
    // loop again.
    let mut scratch: Vec<u8> = Vec::new();
    loop {
        // A stop still writes what was accepted before it: those
        // batches were queued before the flag, so once the flag is
        // seen the queue is drained without waiting and the loop
        // leaves on the first empty look (the stack's last resets ride
        // exactly those batches).
        let stopping = shared.stopped.load(Ordering::Acquire);
        let wait = if stopping {
            std::time::Duration::ZERO
        } else {
            std::time::Duration::from_millis(50)
        };
        let mut batch = match writes.recv_timeout(wait) {
            Ok(batch) => batch,
            Err(mpsc::RecvTimeoutError::Timeout) if stopping => return,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("vfawn: tun writer stopped: writers gone");
                return;
            }
        };
        let outcome = send_batch(&device.0, vnet, &mut batch, &mut scratch);
        // The buffers' bytes are in the kernel; a pool that owns them
        // takes them back here, and without one the drop is the
        // honest end.
        if let Some(release) = shared.release.lock().expect("write release").as_ref() {
            release(&mut batch);
        }
        if let Err(error) = outcome {
            // A queue that cannot take the batch right now is
            // backpressure, not death: the drop behaves like a qdisc
            // drop (TCP above retransmits, UDP loses one datagram),
            // which beats taking the whole interface down
            // mid-transfer — the kernel removes the device with the
            // last fd, and every route falls through to a bypass.
            if error.kind() == ErrorKind::NotConnected {
                eprintln!("vfawn: tun writer stopped: device down");
                shared.stopped.store(true, Ordering::Release);
                return;
            }
            drop_counter = drop_counter.wrapping_add(1);
            if drop_counter == 1 || drop_counter.is_multiple_of(10_000) {
                eprintln!("vfawn: tun write refused ({error}); dropped {drop_counter} batches");
            }
        }
    }
}

/// One write batch onto the wire: one kernel call per frame. The
/// offload path stages each frame behind its virtio header first; the
/// plain path hands the batch's own buffers over untouched.
fn send_batch(
    device: &SyncDevice,
    vnet: bool,
    batch: &mut [BytesMut],
    scratch: &mut Vec<u8>,
) -> io::Result<()> {
    if !vnet {
        // Without the virtio header the headroom is the only thing to
        // undo: frames born in the pool carry it (their first byte is
        // the zero the pool left there), control frames built bare do
        // not, and no packet on the wire starts with a zero byte.
        for frame in batch.iter() {
            let head = usize::from(frame.first() == Some(&0)) * VIRTIO_NET_HDR_LEN;
            device.send(&frame[head..])?;
        }
        return Ok(());
    }
    // One frame, one write: merging the batch into GSO super-packets
    // looked like the offload win but built a standing queue in the
    // kernel's segmentation path — the peer's acknowledgments paced
    // against a twenty-millisecond backlog and every metric sagged
    // (the single flow held half of what plain frames sustain; the
    // eight-flow retransmission count ran double). The per-frame
    // syscall is the cheaper tax on the writer thread, which has a
    // core of its own.
    for frame in batch.iter() {
        if frame.first() == Some(&0) {
            // Born pooled: the headroom IS the virtio header — the
            // zeros say no-offload honestly — and the frame reaches
            // the kernel without a single copy.
            device.send(frame)?;
        } else {
            // Built bare: the header is staged in front, the one copy
            // the control frames' rarity can well afford.
            scratch.clear();
            scratch.resize(VIRTIO_NET_HDR_LEN, 0);
            scratch.extend_from_slice(frame);
            device.send(scratch)?;
        }
    }
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
        // Ownership moves, bytes never copy. A batch wider than `bufs`
        // keeps its tail for the next call: truncating it here lost
        // every segment of a GRO burst past the caller's eighth.
        let count = read_queue::fill(reads, &mut self.leftover, bufs);
        if count > 0 {
            // Room was made: a batch the I/O thread holds can go now.
            self.shared.backlog.wake();
        }
        Ok(count)
    }

    fn write_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
        let batch: Vec<BytesMut> = bufs.iter_mut().map(std::mem::take).collect();
        let count = batch.len();
        // Channel depth is the backpressure; the writer thread's
        // blocking receive is the wake — no event fd rides the write
        // path any more (one trigger per batch was thousands of extra
        // syscalls per second on the reader once the downlink filled
        // the pipe).
        if self.shared.writes.send(batch).is_err() {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
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
            leftover: VecDeque::new(),
            caps: self.caps,
            name: self.name.clone(),
        }))
    }

    fn set_write_release(&self, release: vfawn_core::device::FrameRelease) {
        *self.shared.release.lock().expect("write release") = Some(release);
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
