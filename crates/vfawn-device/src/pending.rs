// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Placeholder for targets whose device plumbing has not landed yet.

use bytes::BytesMut;
use std::io;
use std::io::ErrorKind;
use vfawn_core::{DeviceCaps, DeviceConfig, PacketDevice};

/// A device type that cannot be constructed on this target; creation
/// reports the platform as unsupported until its backend lands.
pub struct TunDevice;

impl TunDevice {
    pub fn create(_config: &DeviceConfig) -> io::Result<Self> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "no device backend for this target yet",
        ))
    }

    /// The interface name; creation already failed on these targets, so
    /// the same failure carries through.
    pub fn name(&self) -> io::Result<String> {
        Err(unsupported())
    }
}

/// Every method reports the same error, so callers can compile against
/// this type on any platform and see a clear runtime failure on targets
/// whose backend has not landed.
impl PacketDevice for TunDevice {
    fn read_batch(&mut self, _bufs: &mut [BytesMut]) -> io::Result<usize> {
        Err(unsupported())
    }

    fn write_batch(&mut self, _bufs: &[BytesMut]) -> io::Result<usize> {
        Err(unsupported())
    }

    fn capabilities(&self) -> DeviceCaps {
        DeviceCaps::MINIMAL
    }

    fn shutdown(&self) -> io::Result<()> {
        Ok(())
    }

    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        Err(unsupported())
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        ErrorKind::Unsupported,
        "no device backend for this target yet",
    )
}
