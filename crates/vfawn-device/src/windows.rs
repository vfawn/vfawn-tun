// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Windows TUN device on top of tun-rs's wintun backend.
//!
//! wintun moves packets through a ring buffer the driver owns; the
//! userspace side pops one packet per call and parks on the ring's
//! event when empty — there is no vectored interface to batch over,
//! so the honest shape is one packet per read with the ring itself as
//! the kernel-side queue. The wintun driver library ships inside the
//! binary, extracted per process to a temp file, so deployment needs
//! no external DLL; the pipeline sees the same raw-IP framing every
//! other platform hands it.

use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread;

use bytes::BytesMut;
use tun_rs::{DeviceBuilder, InterruptEvent, SyncDevice};
use vfawn_core::{DeviceCaps, DeviceConfig, PacketDevice};

/// Frame budget when the configuration leaves the MTU to the platform.
const DEFAULT_MTU: u32 = 65535;

/// How many read batches and write batches may queue between the I/O
/// thread and the callers before the sending side applies backpressure.
const READ_DEPTH: usize = 1024;
const WRITE_DEPTH: usize = 1024;

/// Everything the handles share with the I/O thread.
struct Shared {
    reads: SyncSender<Vec<BytesMut>>,
    writes: SyncSender<Vec<BytesMut>>,
    /// The parked read's knock: a write (or a shutdown) triggers the
    /// event so the I/O thread sees the batch now instead of at the
    /// next packet.
    event: Arc<InterruptEvent>,
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
        self.shared.event.trigger()
    }
}

impl TunDevice {
    /// Create and bring up a device as described by `config`.
    ///
    /// The interface receives the first configured IPv4 address and every
    /// configured IPv6 address; on Windows the address carries the
    /// prefix and the library's route manager handles the interface
    /// route.
    pub fn create(config: &DeviceConfig) -> io::Result<Self> {
        let mtu = effective_mtu(config.mtu);
        let mut builder = DeviceBuilder::new()
            .mtu(mtu as u16)
            .wintun_file(extract_wintun_dll()?);
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
        Ok(self.name.clone().unwrap_or_else(|| "tun0".to_string()))
    }

    /// Adopt a descriptor supplied by the host. This platform has no
    /// such thing: a wintun adapter is adopted by name (the device
    /// creation path opens an existing adapter under the configured
    /// name), and a bare handle carries none of the ring state a
    /// session needs. The call answers with
    /// [`io::ErrorKind::Unsupported`] rather than pretending.
    ///
    /// # Safety
    ///
    /// The descriptor is not consumed; the caller keeps its ownership.
    ///
    /// The body touches nothing — no descriptor, no system state; the
    /// error is the whole answer.
    #[expect(unsafe_code)]
    pub unsafe fn from_fd(_fd: std::os::windows::io::RawSocket) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "wintun adapters are adopted by name; descriptor adoption is a Unix concept",
        ))
    }

    /// A handle through which another thread can stop the device.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    fn spawn_io(device: SyncDevice, caps: DeviceCaps) -> io::Result<Self> {
        let name = device.name()?;
        let event = Arc::new(InterruptEvent::new()?);
        let (read_tx, read_rx) = mpsc::sync_channel(READ_DEPTH);
        let (write_tx, write_rx) = mpsc::sync_channel(WRITE_DEPTH);
        let shared = Arc::new(Shared {
            reads: read_tx,
            writes: write_tx,
            event: Arc::clone(&event),
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

/// Write the embedded wintun driver library to a per-process temp
/// file and return its path. The driver library has no stable ABI
/// placement on this platform: loading wants a file path, and a
/// per-process name keeps concurrent instances from racing one
/// another's extraction. The temp directory's lifetime is the
/// operating system's business, as it is for every installer on this
/// platform.
fn extract_wintun_dll() -> io::Result<String> {
    #[cfg(target_arch = "x86_64")]
    const DLL: &[u8] = include_bytes!("../resources/wintun/x86_64/wintun.dll");
    #[cfg(target_arch = "x86")]
    const DLL: &[u8] = include_bytes!("../resources/wintun/x86/wintun.dll");
    #[cfg(target_arch = "aarch64")]
    const DLL: &[u8] = include_bytes!("../resources/wintun/aarch64/wintun.dll");
    #[cfg(target_arch = "arm")]
    const DLL: &[u8] = include_bytes!("../resources/wintun/arm/wintun.dll");

    let path = std::env::temp_dir().join(format!("vfawn-wintun-{}.dll", std::process::id()));
    std::fs::write(&path, DLL)?;
    Ok(path.to_string_lossy().into_owned())
}

/// The I/O thread: one descriptor, two directions, one loop. The ring
/// is the queue; the loop drains everything it holds behind one
/// interruptible park, and writes leave as one driver call per packet
/// — the ring takes them at memory speed, and a full ring is qdisc
/// loss the peer's recovery re-asks for, not a reason to die.
fn io_loop(shared: Arc<Shared>, device: SyncDevice, writes: Receiver<Vec<BytesMut>>) {
    let seg = 1514;
    let mut buf = BytesMut::zeroed(seg);
    let mut refused: u64 = 0;

    loop {
        // Writes first: a batch already waiting is worth more than
        // one more park.
        loop {
            match writes.try_recv() {
                Ok(batch) => {
                    for frame in &batch {
                        if device.send(frame).is_err() {
                            // A full ring is qdisc-shaped loss: the
                            // peer's loss recovery re-asks, and the
                            // interface lives on. Only the device's
                            // death stops the loop, and its read side
                            // reports that.
                            refused = refused.wrapping_add(1);
                            if refused == 1 || refused.is_multiple_of(10_000) {
                                eprintln!("vfawn: tun send refused; refused {refused} frames");
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
        if shared.stopped.load(Ordering::Acquire) {
            return;
        }

        // One packet; the park is interruptible by the write side's
        // knock and the shutdown flag's.
        buf.clear();
        buf.resize(seg, 0);
        match device.recv_intr(&mut buf, &shared.event) {
            Ok(n) if n > 0 => {
                let frame = buf.split_to(n);
                match shared.reads.try_send(vec![frame]) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_dropped)) => {}
                    Err(TrySendError::Disconnected(_)) => {
                        eprintln!("vfawn: tun I/O stopped: reader gone");
                        return;
                    }
                }
                shared.event.reset().ok();
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::Interrupted => {
                // The knock or the flag: loop and re-read the world.
                shared.event.reset().ok();
            }
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
        // One packet rides each message by construction — the ring's
        // pop is one packet per call — so the swap never truncates.
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

    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        Ok(Box::new(TunDevice {
            shared: Arc::clone(&self.shared),
            reads: None,
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

    /// The embedded driver library lands on disk whole: this is the
    /// deployment path, so its output is what the loader will read.
    /// Loading it needs the driver service, which a unit test does
    /// not assume.
    #[test]
    fn the_embedded_driver_lands_whole() {
        let path = extract_wintun_dll().expect("extraction");
        let written = std::fs::read(&path).expect("the extracted file reads back");
        #[cfg(target_arch = "x86_64")]
        const DLL: &[u8] = include_bytes!("../resources/wintun/x86_64/wintun.dll");
        #[cfg(target_arch = "x86")]
        const DLL: &[u8] = include_bytes!("../resources/wintun/x86/wintun.dll");
        #[cfg(target_arch = "aarch64")]
        const DLL: &[u8] = include_bytes!("../resources/wintun/aarch64/wintun.dll");
        #[cfg(target_arch = "arm")]
        const DLL: &[u8] = include_bytes!("../resources/wintun/arm/wintun.dll");
        assert_eq!(written, DLL, "byte-for-byte with the embedded library");
        let _ = std::fs::remove_file(&path);
    }
}
