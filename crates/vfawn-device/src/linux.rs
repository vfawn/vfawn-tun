// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Linux TUN device on top of tun-rs.

use std::io;
use std::io::ErrorKind;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::BytesMut;
use tun_rs::{DeviceBuilder, InterruptEvent, SyncDevice};
use vfawn_core::{DeviceCaps, DeviceConfig, PacketDevice};

/// Frame budget when the configuration leaves the MTU to the platform.
/// Large frames keep the syscall rate down; the kernel never reads past
/// the end of an actual packet, so the slack costs address space only.
const DEFAULT_MTU: u32 = 65535;

/// The MTU in force for buffer sizing, after platform derivation.
fn effective_mtu(explicit: u32) -> u32 {
    if explicit == 0 { DEFAULT_MTU } else { explicit }
}

/// A live TUN device.
///
/// One queue, no offload: that is the honest capability floor until
/// offload negotiation lands. Reads are interruptible through a pipe event
/// so [`PacketDevice::shutdown`] wakes a blocked reader from any thread.
pub struct TunDevice {
    device: SyncDevice,
    event: Arc<InterruptEvent>,
    sizes: Vec<usize>,
    original: Vec<u8>,
    mtu: usize,
    caps: DeviceCaps,
    stopped: Arc<AtomicBool>,
}

/// A detached shutdown control for a device owned by another thread.
///
/// The data-plane loop owns the device; signal handlers and management
/// code hold this handle instead.
pub struct ShutdownHandle {
    event: Arc<InterruptEvent>,
    stopped: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Request shutdown and wake any blocked reader. Idempotent.
    pub fn shutdown(&self) -> io::Result<()> {
        self.stopped.store(true, Ordering::Release);
        self.event.trigger()
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
        Self::wrap(device, mtu as usize, caps)
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
        // The kernel exposes no cheap way to read the MTU back off an
        // adopted fd; size for the platform default, which is an upper
        // bound for anything a host would hand over.
        let caps = DeviceCaps::MINIMAL;
        Self::wrap(device, DEFAULT_MTU as usize, caps)
    }

    fn wrap(device: SyncDevice, mtu: usize, caps: DeviceCaps) -> io::Result<Self> {
        let event = InterruptEvent::new()?;
        let stopped = Arc::new(AtomicBool::new(false));
        Ok(TunDevice {
            device,
            event: Arc::new(event),
            sizes: vec![0; 8],
            // Headroom over the MTU keeps the GRO read path, which lands
            // with offload, from ever truncating a merged packet.
            original: vec![0; mtu + 64],
            mtu,
            caps,
            stopped,
        })
    }

    /// A handle through which another thread can stop this device.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            event: self.event.clone(),
            stopped: self.stopped.clone(),
        }
    }
}

impl PacketDevice for TunDevice {
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        if self.stopped.load(Ordering::Acquire) {
            return Ok(0);
        }
        if bufs.is_empty() {
            return Ok(0);
        }
        for buf in bufs.iter_mut() {
            if buf.len() < self.mtu {
                buf.resize(self.mtu, 0);
            }
        }
        self.sizes.resize(bufs.len(), 0);
        // Without vnet headers the call delivers one packet into the first
        // buffer and returns one; splitting one merged read across the
        // batch only happens on the GRO path, which arrives with offload.
        // Either way the contract below holds: filled buffers are truncated
        // to their packet sizes.
        let outcome = self.device.recv_multiple_intr(
            &mut self.original,
            bufs,
            &mut self.sizes,
            0,
            &self.event,
        );
        match outcome {
            Ok(count) => {
                for (index, size) in self.sizes.iter().enumerate().take(count) {
                    bufs[index].truncate(*size);
                }
                Ok(count)
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {
                self.stopped.store(true, Ordering::Release);
                Ok(0)
            }
            Err(error) => Err(error),
        }
    }

    fn write_batch(&mut self, bufs: &[BytesMut]) -> io::Result<usize> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
        // With no vnet headers there is nothing to coalesce, so a batch is
        // a send per packet; the coalescing variant arrives together with
        // offload negotiation.
        let mut written = 0;
        for buf in bufs {
            self.device.send(buf)?;
            written += 1;
        }
        Ok(written)
    }

    fn capabilities(&self) -> DeviceCaps {
        self.caps
    }

    fn shutdown(&self) -> io::Result<()> {
        ShutdownHandle {
            event: self.event.clone(),
            stopped: self.stopped.clone(),
        }
        .shutdown()
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

    #[test]
    fn capability_floor_is_single_queue_without_offload() {
        // What a fresh device reports today; offload and multi-queue
        // negotiation will replace the floor, not bypass the reporting.
        let caps = DeviceCaps::MINIMAL;
        assert!(!caps.gso && !caps.gro);
        assert_eq!(caps.queues, 1);
    }
}
