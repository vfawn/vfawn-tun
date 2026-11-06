// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Darwin TUN device on top of tun-rs's utun backend.
//!
//! utun moves exactly one packet per syscall and offers no kernel
//! offload: the I/O thread's budget is the syscall count, so the loop
//! reads until the kernel has nothing more and writes in the batches
//! the pipeline hands it. The four-byte address-family prefix utun
//! adds to every packet is the library's own business; this layer
//! sees the same raw-IP framing the Linux path does.

use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread;

use bytes::BytesMut;
use tun_rs::{DeviceBuilder, SyncDevice};
use vfawn_core::{DeviceCaps, DeviceConfig, PacketDevice};

/// Frame budget when the configuration leaves the MTU to the platform.
const DEFAULT_MTU: u32 = 65535;

/// How many read batches and write batches may queue between the I/O
/// thread and the callers before the sending side applies backpressure.
const READ_DEPTH: usize = 1024;
const WRITE_DEPTH: usize = 1024;

/// The MTU in force for buffer sizing, after platform derivation.
fn effective_mtu(explicit: u32) -> u32 {
    if explicit == 0 { DEFAULT_MTU } else { explicit }
}

/// Everything the handles share with the I/O thread.
struct Shared {
    reads: SyncSender<Vec<BytesMut>>,
    writes: SyncSender<Vec<BytesMut>>,
    stopped: AtomicBool,
}

/// One end of the device: the reader's half by construction, the
/// writer's half through [`PacketDevice::duplicate`], which shares
/// the same I/O thread and channels.
pub struct TunDevice {
    shared: Arc<Shared>,
    reads: Option<Receiver<Vec<BytesMut>>>,
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
        let (read_tx, read_rx) = mpsc::sync_channel(READ_DEPTH);
        let (write_tx, write_rx) = mpsc::sync_channel(WRITE_DEPTH);
        let shared = Arc::new(Shared {
            reads: read_tx,
            writes: write_tx,
            stopped: AtomicBool::new(false),
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
/// utun is strictly synchronous: each read() returns one packet or
/// blocks, each write() sends one packet. The loop reads until the
/// kernel has nothing more, pushes the batch, then drains any writes
/// the pipeline queued before going back to reading.
fn io_loop(shared: Arc<Shared>, device: SyncDevice, writes: Receiver<Vec<BytesMut>>) {
    let seg = 1514;
    let mut buf = BytesMut::zeroed(seg);

    loop {
        // Writes first: a batch already waiting is worth more than one
        // more poll.
        loop {
            match writes.try_recv() {
                Ok(batch) => {
                    for frame in &batch {
                        if device.send(frame).is_err() {
                            eprintln!("vfawn: tun I/O stopped: device down");
                            shared.stopped.store(true, Ordering::Release);
                            return;
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
        // Read one packet; utun is blocking, so this parks until a
        // frame arrives or the device goes away.
        buf.clear();
        buf.resize(seg, 0);
        match device.recv(&mut buf) {
            Ok(n) if n > 0 => {
                let frame = buf.split_to(n);
                match shared.reads.try_send(vec![frame]) {
                    Ok(()) => {}
                    Err(std::sync::mpsc::TrySendError::Full(_)) => {}
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                        eprintln!("vfawn: tun I/O stopped: reader gone");
                        return;
                    }
                }
                // One packet per iteration is the honest shape on
                // utun: each read is a syscall, and there is no
                // nonblocking drain to batch. The pipeline's channel
                // does the batching.
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotConnected => {
                eprintln!("vfawn: tun I/O stopped: device down");
                shared.stopped.store(true, Ordering::Release);
                return;
            }
            Err(_) => {
                // A transient read error loses one packet, not the
                // interface.
            }
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
        let mut frames = match reads.recv_timeout(std::time::Duration::from_millis(50)) {
            Ok(frames) => frames,
            Err(_) => return Ok(0),
        };
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

    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        Ok(Box::new(TunDevice {
            shared: Arc::clone(&self.shared),
            reads: None,
            caps: self.caps,
            name: self.name.clone(),
        }))
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
