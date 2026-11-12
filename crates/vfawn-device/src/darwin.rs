// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Darwin TUN device on top of tun-rs's utun backend.
//!
//! utun has no vectored kernel interface; what it does have is the
//! extended-message batch syscall for reads (recvmsg_x over the
//! kernel's msghdr_x) and a pending-packets queue whose depth the
//! control socket accepts by option. The I/O thread therefore runs
//! the utun descriptor itself: a nonblocking recvmsg_x drains
//! everything the kernel queued behind one kqueue park, and writes
//! leave as one writev per packet (the batch send syscall exists but
//! stays off — see the note on the write path). The four-byte
//! address-family prefix utun adds to every packet is this layer's
//! own business; the pipeline sees the same raw-IP framing the Linux
//! path hands it.

use std::collections::VecDeque;
use std::io;
use std::io::ErrorKind;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread;

use bytes::BytesMut;
use tun_rs::{DeviceBuilder, SyncDevice};
use vfawn_core::{DeviceCaps, DeviceConfig, PacketDevice};

use crate::read_queue::{self, Backlog, Delivery};

/// Frame budget when the configuration leaves the MTU to the platform.
const DEFAULT_MTU: u32 = 65535;

/// How many read batches and write batches may queue between the I/O
/// thread and the callers before the sending side applies backpressure.
const READ_DEPTH: usize = 1024;
const WRITE_DEPTH: usize = 1024;

/// The read slot budget, in bytes: the number of extended-message
/// slots submitted per recvmsg_x is this budget over the frame size,
/// so the per-call memory stays flat whatever the MTU.
const READ_BUDGET: usize = 512 * 1024;

/// The receive-buffer ladder for the control socket: try each size
/// until the kernel accepts one, then read back what stuck.
const RCVBUF_TARGET: usize = 8 << 20;
const RCVBUF_FLOOR: usize = 1 << 20;

/// The ceiling on the pending-packets queue depth. The derivation
/// from the receive buffer already lands low; the clamp keeps a
/// pathological buffer value from arming a queue the drain rate
/// cannot feed.
const MAX_PENDING: usize = 64;

/// SYSPROTO_CONTROL's utun option for the pending-packets queue.
const UTUN_OPT_MAX_PENDING_PACKETS: libc::c_int = 16;

/// The extended-message batch read syscall, from the system's own
/// syscall tables (the C library does not export its number).
const SYS_RECVMSG_X: libc::c_int = 480;

/// The kernel's extended message header: the socket header plus the
/// data byte count the kernel reports per slot.
#[repr(C)]
struct MsgHdrX {
    msg: libc::msghdr,
    datalen: u32,
}

/// The doorbell pipe: writes and shutdowns drop a byte in the write
/// end so the I/O thread's kqueue park ends now instead of at the
/// next packet. A pipe, not a channel, because kqueue watches
/// descriptors.
struct WakePipe {
    read: RawFd,
    write: RawFd,
}

impl WakePipe {
    /// A nonblocking pipe on both ends: the ringer never waits, and a
    /// full pipe means the bell already rang.
    fn new() -> io::Result<Self> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: a pipe into stack storage this call owns.
        #[expect(unsafe_code)]
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let pipe = Self {
            read: fds[0],
            write: fds[1],
        };
        // SAFETY: flag words on descriptors created a line above.
        #[expect(unsafe_code)]
        unsafe {
            for fd in [pipe.read, pipe.write] {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                    let error = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(error);
                }
            }
        }
        Ok(pipe)
    }

    /// Ring the bell. Never blocks, never fails the caller: a byte
    /// that does not fit means the bell is already rung.
    fn ring(&self) {
        // SAFETY: one byte into the write end of a pipe this process
        // owns, nonblocking.
        #[expect(unsafe_code)]
        unsafe {
            libc::write(self.write, "x".as_ptr().cast(), 1);
        }
    }

    /// Drain the bell so a stale ring does not spin the park.
    fn drain(&self) {
        let mut scratch = [0u8; 64];
        // SAFETY: reads into stack storage from the read end this
        // process owns, nonblocking.
        #[expect(unsafe_code)]
        unsafe {
            libc::read(self.read, scratch.as_mut_ptr().cast(), scratch.len());
        }
    }
}

impl Drop for WakePipe {
    fn drop(&mut self) {
        // SAFETY: closing both ends of a pipe whose ownership ends
        // here.
        #[expect(unsafe_code)]
        unsafe {
            libc::close(self.read);
            libc::close(self.write);
        }
    }
}

/// Everything the handles share with the I/O thread. The pipe keeps
/// the whole set alive: the last handle out closes it, and with it
/// the descriptors.
struct Shared {
    reads: SyncSender<Vec<BytesMut>>,
    writes: SyncSender<Vec<BytesMut>>,
    wake: Arc<WakePipe>,
    stopped: AtomicBool,
    backlog: Backlog,
}

impl Shared {
    /// Wake the I/O thread wherever it waits: the kqueue park through
    /// the bell, a held batch's park through the backlog.
    fn wake(&self) {
        self.backlog.wake();
        self.wake.ring();
    }
}

/// One end of the device: the reader's half by construction, the
/// writer's half through [`PacketDevice::duplicate`], which shares
/// the same I/O thread and channels.
pub struct TunDevice {
    shared: Arc<Shared>,
    reads: Option<Receiver<Vec<BytesMut>>>,
    /// Frames of a batch the caller's buffer could not take in one
    /// call; the next call serves these before another batch lands.
    leftover: VecDeque<BytesMut>,
    caps: DeviceCaps,
    name: Option<String>,
}

/// A detached shutdown control for a device owned by another thread.
pub struct ShutdownHandle {
    shared: Arc<Shared>,
}

impl ShutdownHandle {
    /// Request shutdown. Idempotent.
    pub fn shutdown(&self) -> io::Result<()> {
        self.shared.stopped.store(true, Ordering::Release);
        self.shared.wake();
        Ok(())
    }
}

impl TunDevice {
    /// Create and bring up a device as described by `config`.
    ///
    /// The interface receives the first configured IPv4 address and every
    /// configured IPv6 address; on darwin the address carries the
    /// prefix and the library's route manager handles the interface
    /// route.
    pub fn create(config: &DeviceConfig) -> io::Result<Self> {
        let mtu = effective_mtu(config.mtu);
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
    pub fn name(&self) -> io::Result<String> {
        Ok(self.name.clone().unwrap_or_else(|| "utun0".to_string()))
    }

    /// Adopt a device fd supplied by the host, as VPN services and
    /// network extensions do.
    ///
    /// # Safety
    ///
    /// The caller guarantees the framing contract and ownership.
    #[expect(unsafe_code)]
    pub unsafe fn from_fd(fd: std::os::fd::RawFd) -> io::Result<Self> {
        // SAFETY: the contract above is the caller's to uphold.
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
        let fd = device.as_raw_fd();
        let mtu = device.mtu().map(u32::from).unwrap_or(DEFAULT_MTU).max(1) as usize;
        configure_utun(fd, mtu)?;
        let wake = Arc::new(WakePipe::new()?);
        let (read_tx, read_rx) = mpsc::sync_channel(READ_DEPTH);
        let (write_tx, write_rx) = mpsc::sync_channel(WRITE_DEPTH);
        let shared = Arc::new(Shared {
            reads: read_tx,
            writes: write_tx,
            wake: Arc::clone(&wake),
            stopped: AtomicBool::new(false),
            backlog: Backlog::default(),
        });
        let io_shared = Arc::clone(&shared);
        thread::Builder::new()
            .name("vfawn-tun-io".into())
            .spawn(move || io_loop(io_shared, device, write_rx, mtu))?;
        Ok(TunDevice {
            shared,
            reads: Some(read_rx),
            leftover: VecDeque::new(),
            caps,
            name: Some(name),
        })
    }
}

/// Put the utun descriptor in the shape the batch loop wants: always
/// nonblocking, with a raised receive buffer and a pending-packets
/// queue sized from it. The queue derivation follows the kernel's own
/// accounting — the control socket refuses writes once the queued
/// bytes reach the receive buffer, while reaching the pending-packet
/// cap pauses the interface until a read — so the cap lands where the
/// byte budget and the packet budget agree.
fn configure_utun(fd: RawFd, mtu: usize) -> io::Result<()> {
    // SAFETY: fcntl on a live descriptor this process owns.
    #[expect(unsafe_code)]
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: setting a flag word read a line above on the same fd.
    #[expect(unsafe_code)]
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let rcvbuf = raise_receive_buffer(fd);
    let pending = (rcvbuf / 8 * 7 / (mtu + 4)).clamp(1, MAX_PENDING) as libc::c_int;
    // SAFETY: a plain integer socket option on a descriptor this
    // process owns; the value is a validated, clamped count.
    #[expect(unsafe_code)]
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            UTUN_OPT_MAX_PENDING_PACKETS,
            &pending as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Climb the receive-buffer ladder and return what the kernel kept.
/// The kernel doubles what a setsockopt requests, so the readback is
/// the honest number, not the ask.
fn raise_receive_buffer(fd: RawFd) -> usize {
    let mut size = RCVBUF_TARGET;
    while size >= RCVBUF_FLOOR {
        // SAFETY: a plain integer socket option on a descriptor this
        // process owns.
        #[expect(unsafe_code)]
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const usize as *const libc::c_void,
                std::mem::size_of::<usize>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            break;
        }
        size /= 2;
    }
    let mut kept = 0usize;
    let mut len = std::mem::size_of::<usize>() as libc::socklen_t;
    // SAFETY: the readback of the option above into matching storage.
    #[expect(unsafe_code)]
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut kept as *mut usize as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || kept == 0 {
        RCVBUF_FLOOR
    } else {
        kept
    }
}

/// One submitted read slot: the family prefix the kernel writes and
/// the frame buffer behind it. The buffer becomes the outbound frame
/// by a split, so a packet crosses to the pipeline without a copy.
struct ReadSlot {
    frame: BytesMut,
}

/// Rebuild the extended-message headers for one batch read. Headers
/// are rebuilt whole every call — older kernels reject a slot whose
/// stale fields are merely length-zeroed — with two iovecs per slot:
/// the four-byte family prefix, then the frame buffer at full MTU.
///
/// # Safety
///
/// The slot storage must outlive the syscall that consumes the
/// headers: the caller keeps `slots`, `headers`, and `iovecs` alive
/// in one stack frame without mutating the slots until the syscall
/// returns.
#[expect(unsafe_code)]
unsafe fn submit_read(
    slots: &mut [ReadSlot],
    headers: &mut Vec<MsgHdrX>,
    iovecs: &mut Vec<[libc::iovec; 2]>,
) {
    headers.clear();
    iovecs.clear();
    for slot in slots.iter_mut() {
        if slot.frame.len() < slot.frame.capacity() {
            slot.frame.resize(slot.frame.capacity(), 0);
        }
        iovecs.push([
            libc::iovec {
                iov_base: slot.frame.as_mut_ptr().cast(),
                iov_len: 4,
            },
            libc::iovec {
                // SAFETY: the frame buffer is offset by the four
                // prefix bytes the kernel writes ahead of it.
                iov_base: unsafe { slot.frame.as_mut_ptr().add(4) }.cast(),
                iov_len: slot.frame.len() - 4,
            },
        ]);
    }
    for iovec in iovecs.iter_mut() {
        headers.push(MsgHdrX {
            msg: libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iovec.as_mut_ptr().cast(),
                msg_iovlen: 2,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            datalen: 0,
        });
    }
}

/// The address-family prefix utun wants ahead of an outbound frame,
/// by the frame's own IP version nibble. The word is in network byte
/// order, as the kernel's framer writes it and its demux reads it back
/// (sing-tun's packetHeader4/6, tun_darwin.go:191). A host-order word
/// still ticks the interface's input counter, which runs ahead of the
/// demux, and then every frame dies there unseen.
fn family_prefix(frame: &[u8]) -> [u8; 4] {
    let family: u32 = match frame.first().map(|byte| byte >> 4) {
        Some(6) => libc::AF_INET6 as u32,
        _ => libc::AF_INET as u32,
    };
    family.to_be_bytes()
}

/// The I/O thread: one descriptor, two directions, one loop. Reads
/// drain everything the kernel queued behind a single kqueue park;
/// writes leave one writev per packet. The write side stays
/// per-packet on purpose: the batch send syscall pushes past the
/// kernel's utun input drain rate, and once its queue caps out the
/// kernel rejects writes while leaking the packet's buffer — a
/// device-wide loss that only a reboot clears. writev's own cost
/// keeps the rate under the ceiling.
fn io_loop(shared: Arc<Shared>, device: SyncDevice, writes: Receiver<Vec<BytesMut>>, mtu: usize) {
    let fd = device.as_raw_fd();
    let slot_count = (READ_BUDGET / mtu).max(1) + 1;
    let mut slots: Vec<ReadSlot> = (0..slot_count)
        .map(|_| ReadSlot {
            frame: BytesMut::zeroed(mtu + 4),
        })
        .collect();
    let mut headers: Vec<MsgHdrX> = Vec::with_capacity(slot_count);
    let mut iovecs: Vec<[libc::iovec; 2]> = Vec::with_capacity(slot_count);
    let mut frames: Vec<BytesMut> = Vec::with_capacity(slot_count);
    let mut prefix: [u8; 4] = [0; 4];
    let mut refused: u64 = 0;
    shared.backlog.register();
    // A batch the read channel had no room for: while it waits nothing
    // more is read, and the backlog stays in the kernel's utun queue
    // (read_queue.rs says why).
    let mut held: Option<Vec<BytesMut>> = None;

    // The park: the descriptor for packets, the wake pipe for writes
    // and shutdowns. Registered once, level-triggered.
    // SAFETY: kqueue and kevent on descriptors this thread owns for
    // its whole life; the event arrays are stack-local.
    #[expect(unsafe_code)]
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        eprintln!("vfawn: tun I/O stopped: kqueue failed");
        shared.stopped.store(true, Ordering::Release);
        return;
    }
    #[expect(unsafe_code)]
    unsafe {
        let mut changes = [
            libc::kevent {
                ident: fd as usize,
                filter: libc::EVFILT_READ,
                flags: libc::EV_ADD | libc::EV_ENABLE,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            },
            libc::kevent {
                ident: shared.wake.read as usize,
                filter: libc::EVFILT_READ,
                flags: libc::EV_ADD | libc::EV_ENABLE,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            },
        ];
        if libc::kevent(
            kq,
            changes.as_mut_ptr(),
            2,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        ) < 0
        {
            eprintln!("vfawn: tun I/O stopped: kqueue register failed");
            shared.stopped.store(true, Ordering::Release);
            return;
        }
    }

    loop {
        // Read before the writes: a batch accepted before the stop was
        // queued before the flag, so the drain below still carries it
        // (the stack's last resets ride exactly that batch) and only
        // then does the loop leave.
        let stopping = shared.stopped.load(Ordering::Acquire);
        // Writes first: a batch already waiting is worth more than
        // one more park.
        loop {
            match writes.try_recv() {
                Ok(batch) => {
                    for frame in &batch {
                        if frame.is_empty() {
                            continue;
                        }
                        // The pooled emitter's headroom: the first
                        // zero byte names ten bytes no utun wants, and
                        // the slice keeps the buffer whole for the
                        // pool's return trip.
                        let head = usize::from(frame[0] == 0) * vfawn_wire::VNET_HEADROOM;
                        let frame = &frame[head..];
                        prefix.copy_from_slice(&family_prefix(frame));
                        let pair = [
                            libc::iovec {
                                iov_base: prefix.as_mut_ptr().cast(),
                                iov_len: prefix.len(),
                            },
                            libc::iovec {
                                iov_base: frame.as_ptr() as *mut libc::c_void,
                                iov_len: frame.len(),
                            },
                        ];
                        // SAFETY: writev on the descriptor this thread
                        // owns, with iovecs pointing at storage this
                        // frame and this stack own for the call.
                        #[expect(unsafe_code)]
                        let written = unsafe { libc::writev(fd, pair.as_ptr(), 2) };
                        if written < 0 {
                            let error = io::Error::last_os_error();
                            if error.kind() == ErrorKind::NotConnected {
                                eprintln!("vfawn: tun I/O stopped: device down");
                                shared.stopped.store(true, Ordering::Release);
                                return;
                            }
                            // A full or busy queue is qdisc-shaped
                            // loss: the peer's loss recovery re-asks,
                            // one datagram is lost, the interface
                            // lives on.
                            refused = refused.wrapping_add(1);
                            if refused == 1 || refused.is_multiple_of(10_000) {
                                eprintln!(
                                    "vfawn: tun write refused ({error}); refused {refused} frames"
                                );
                            }
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
        shared.wake.drain();
        if stopping {
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

        // One batch read of everything the kernel queued.
        // SAFETY: the slot storage outlives the syscall (same frame),
        // and the headers are rebuilt whole before every submit.
        #[expect(unsafe_code)]
        let count = unsafe {
            submit_read(&mut slots, &mut headers, &mut iovecs);
            libc::syscall(
                SYS_RECVMSG_X,
                fd,
                headers.as_mut_ptr(),
                headers.len(),
                libc::MSG_DONTWAIT,
                0,
                0,
            )
        };
        if count > 0 {
            frames.clear();
            for index in 0..count as usize {
                let datalen = headers[index].datalen as usize;
                // The prefix eats four of the reported bytes; the
                // frame is the rest, taken by ownership. A datagram
                // shorter than its own prefix carries no packet.
                let frame_len = datalen.saturating_sub(4).min(mtu);
                if frame_len == 0 {
                    continue;
                }
                let slot = &mut slots[index];
                let mut frame = slot.frame.split_to(frame_len + 4);
                let _ = frame.split_to(4);
                frames.push(frame);
                slot.frame.resize(mtu + 4, 0);
            }
            if !frames.is_empty() {
                match shared
                    .backlog
                    .deliver(&shared.reads, std::mem::take(&mut frames))
                {
                    Delivery::Sent => {}
                    Delivery::Held(batch) => held = Some(batch),
                    Delivery::Gone => {
                        eprintln!("vfawn: tun I/O stopped: reader gone");
                        return;
                    }
                }
            }
            continue;
        }
        if count < 0 {
            let error = io::Error::last_os_error();
            match error.kind() {
                ErrorKind::WouldBlock => {}
                ErrorKind::Interrupted => continue,
                ErrorKind::NotConnected => {
                    eprintln!("vfawn: tun I/O stopped: device down");
                    shared.stopped.store(true, Ordering::Release);
                    return;
                }
                _ => {
                    // A transient read error loses one batch, not the
                    // interface.
                }
            }
        }

        // Park until the descriptor has packets or the bell rings.
        #[expect(unsafe_code)]
        unsafe {
            let mut events = [libc::kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            }; 2];
            libc::kevent(
                kq,
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                2,
                std::ptr::null(),
            );
        }
    }
}

impl PacketDevice for TunDevice {
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        let Some(reads) = &self.reads else {
            return Ok(0);
        };
        if self.shared.stopped.load(Ordering::Acquire) {
            return Ok(0);
        }
        // The leftovers of an earlier oversized batch first: a dropped
        // tail would be silent packet loss the caller can neither see
        // nor pace against.
        let served = read_queue::fill(reads, &mut self.leftover, bufs);
        if served > 0 {
            // Room was made: a batch the I/O thread holds can go now.
            self.shared.backlog.wake();
        }
        Ok(served)
    }

    fn write_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
        let batch: Vec<BytesMut> = bufs.iter_mut().map(std::mem::take).collect();
        let count = batch.len();
        if self.shared.writes.send(batch).is_err() {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
        self.shared.wake();
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

    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        Ok(Box::new(TunDevice {
            shared: Arc::clone(&self.shared),
            reads: None,
            leftover: VecDeque::new(),
            caps: self.caps,
            name: self.name.clone(),
        }))
    }
}

/// The MTU in force for buffer sizing, after platform derivation.
fn effective_mtu(explicit: u32) -> u32 {
    if explicit == 0 { DEFAULT_MTU } else { explicit }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_mtu_selects_the_platform_default() {
        assert_eq!(effective_mtu(0), DEFAULT_MTU);
        assert_eq!(effective_mtu(1500), 1500);
    }

    #[test]
    fn pending_depth_follows_the_buffer_budget() {
        // The kernel's own accounting: the byte budget is seven
        // eighths of the receive buffer, the packet budget is that
        // over a frame plus its prefix. Big buffers ceiling at the
        // clamp; small ones report the raw budget.
        let pending =
            |rcvbuf: usize, mtu: usize| (rcvbuf / 8 * 7 / (mtu + 4)).clamp(1, MAX_PENDING);
        assert_eq!(pending(1 << 21, 1500), MAX_PENDING, "2MiB ceilings");
        assert_eq!(
            pending(1 << 21, 65535),
            27,
            "jumbo frames spend bytes, not slots"
        );
        assert_eq!(pending(64 << 10, 1500), 38, "64KiB reports the raw budget");
        assert_eq!(
            pending(64 << 10, 65535),
            1,
            "a vanished budget floors at one"
        );
        assert_eq!(
            pending(usize::MAX, 1500),
            MAX_PENDING,
            "a pathological buffer ceilings at the clamp"
        );
    }

    #[test]
    fn family_prefix_follows_the_ip_version() {
        // The literal bytes, not a round trip through the same byte
        // order: a host-order prefix passed the round trip and lost
        // every written frame on a live kernel.
        let v4 = family_prefix(&[0x45, 0, 0, 0]);
        let v6 = family_prefix(&[0x60, 0, 0, 0]);
        assert_eq!(v4, [0, 0, 0, libc::AF_INET as u8]);
        assert_eq!(v6, [0, 0, 0, libc::AF_INET6 as u8]);
    }

    #[test]
    fn the_extended_header_is_the_kernel_header_plus_one_word() {
        let kernel = std::mem::size_of::<libc::msghdr>();
        let word = std::mem::size_of::<u32>();
        let align = std::mem::align_of::<libc::msghdr>();
        let padded = kernel + word.div_ceil(align) * align;
        assert_eq!(
            std::mem::size_of::<MsgHdrX>(),
            padded,
            "the extended header pads to the kernel header's alignment"
        );
    }

    /// Creating a utun needs no privileges; the configuration path is
    /// the first thing the batch loop stands on, and a kernel that
    /// refuses the pending-packets option says so here, loudly. A
    /// harness that still refuses the socket keeps the arithmetic
    /// tests and reports the skip.
    #[test]
    fn utun_configuration_takes_the_batch_shape() {
        match DeviceBuilder::new().mtu(1500).build_sync() {
            Ok(device) => {
                configure_utun(device.as_raw_fd(), 1500).expect("pending-packets queue");
            }
            Err(error) => {
                eprintln!("skipping utun shape test: {error}");
            }
        }
    }
}
