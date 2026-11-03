// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Linux TUN device on top of tun-rs.

use std::io;
use std::io::ErrorKind;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::BytesMut;
use tun_rs::{DeviceBuilder, InterruptEvent, SyncDevice, VIRTIO_NET_HDR_LEN};
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
    /// The write side's batch state: a grow-once staging vector of
    /// header-padded frames and the merge table the kernel-facing
    /// batched send consults. Both live only on the Linux offload
    /// path; the per-packet baseline stays for adopted descriptors.
    vnet: bool,
    gro_table: tun_rs::GROTable,
    staging: Vec<BytesMut>,
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
        // The offload path is plumbed but not yet switched on: the
        // multi-queue flag the queue-cloning split needs does not take
        // effect through this builder yet (the clone answers
        // "iff_multi_queue not enabled"), and a half-offloaded device
        // cannot come up at all. The batched-send and merged-receive
        // arms below stay ready for the day the flag does.
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
        // The caps say what this device can actually do: the offload
        // path negotiated vnet headers, which is exactly GSO on send
        // and GRO on receive.
        let caps = DeviceCaps::MINIMAL;
        Self::wrap(device, mtu as usize, caps, false)
    }

    /// The interface name the kernel knows this device by.
    ///
    /// Route orchestration needs the real name: with no configured name
    /// the driver assigns one, and rules and addresses must reference
    /// exactly that.
    pub fn name(&self) -> io::Result<String> {
        self.device.name()
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
        // bound for anything a host would hand over. An adopted
        // descriptor carries no vnet header: the per-packet baseline.
        let caps = DeviceCaps::MINIMAL;
        Self::wrap(device, DEFAULT_MTU as usize, caps, false)
    }

    fn wrap(device: SyncDevice, mtu: usize, caps: DeviceCaps, vnet: bool) -> io::Result<Self> {
        let event = InterruptEvent::new()?;
        let stopped = Arc::new(AtomicBool::new(false));
        Ok(TunDevice {
            device,
            event: Arc::new(event),
            sizes: vec![0; 8],
            // The read scratch carries the vnet header plus the largest
            // merge the kernel may hand back, so a coalesced burst never
            // truncates.
            original: vec![0; VIRTIO_NET_HDR_LEN + 65535],
            mtu,
            caps,
            stopped,
            vnet,
            gro_table: tun_rs::GROTable::default(),
            staging: Vec::new(),
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

    fn write_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(ErrorKind::NotConnected, "device is down"));
        }
        if !self.vnet {
            // The per-packet baseline: an adopted descriptor carries no
            // vnet header, so a batch is a send per frame.
            let count = bufs.len();
            for buf in bufs {
                self.device.send(buf)?;
            }
            return Ok(count);
        }
        // The batched send wants the header slot in front of every
        // frame; staging pays one copy per frame and returns whole-batch
        // writes (with the kernel merging what it can) in exchange.
        let count = bufs.len();
        self.staging.clear();
        for buf in bufs {
            let mut framed = BytesMut::with_capacity(VIRTIO_NET_HDR_LEN + buf.len());
            framed.resize(VIRTIO_NET_HDR_LEN, 0);
            framed.extend_from_slice(buf);
            self.staging.push(framed);
        }
        self.device
            .send_multiple(&mut self.gro_table, &mut self.staging, VIRTIO_NET_HDR_LEN)?;
        Ok(count)
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

    // A dup of the descriptor, not a second queue: the crate's own
    // clone attaches another multi-queue handle, which single-queue
    // devices reject and which would spread flows across readers even
    // where it works. A split read/write bridge wants one shared queue
    // with one reader; a duplicated descriptor gives exactly that.
    #[allow(unsafe_code)]
    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        // The offload path clones a whole second queue: a fresh
        // descriptor attached to the same interface with the vnet
        // header state inherited, which is the only split the library
        // supports for an offloaded device. The plain path (an adopted
        // descriptor, no vnet) keeps the raw dup.
        let cloned = if self.vnet {
            self.device.try_clone()?
        } else {
            use std::os::fd::AsRawFd;
            // SAFETY: dup returns a fresh owned descriptor of a live
            // fd; the device below adopts it and nothing else touches
            // it.
            let twin = unsafe { libc::dup(self.device.as_raw_fd()) };
            if twin < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the fd came from dup above, is valid, and
            // ownership transfers into the device object.
            unsafe { tun_rs::SyncDevice::from_fd(twin)? }
        };
        Ok(Box::new(TunDevice {
            device: cloned,
            event: Arc::clone(&self.event),
            sizes: vec![0; 8],
            original: vec![0; VIRTIO_NET_HDR_LEN + 65535],
            mtu: self.mtu,
            caps: self.caps,
            stopped: Arc::clone(&self.stopped),
            vnet: self.vnet,
            gro_table: tun_rs::GROTable::default(),
            staging: Vec::new(),
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

    #[test]
    fn capability_floor_is_single_queue_without_offload() {
        // What a fresh device reports today; offload and multi-queue
        // negotiation will replace the floor, not bypass the reporting.
        let caps = DeviceCaps::MINIMAL;
        assert!(!caps.gso && !caps.gro);
        assert_eq!(caps.queues, 1);
    }
}
