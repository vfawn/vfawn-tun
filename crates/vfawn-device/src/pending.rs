// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Placeholder for targets whose device plumbing has not landed yet.

use std::io;
use std::io::ErrorKind;
use vfawn_core::DeviceConfig;

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
}
