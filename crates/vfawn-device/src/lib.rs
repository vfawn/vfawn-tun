// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! TUN device access, uniform across platforms.
//!
//! Wraps tun-rs and exposes creation, configuration, batched reads and
//! writes, and capability reporting through the `PacketDevice` contract.
//! Batched I/O is the core abstraction: per-packet syscalls are the first
//! throughput ceiling on any TUN-backed data path, so the contract is
//! batch-shaped from the start even where the underlying implementation
//! fills batches one packet at a time.
//!
//! This crate carries no packet semantics of its own; anything that has
//! to understand a header belongs in `vfawn-wire` or the stacks.

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "android",
    target_os = "ios"
))]
mod read_queue;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::TunDevice;

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::TunDevice;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::TunDevice;

#[cfg(any(target_os = "android", target_os = "ios"))]
mod mobile;
#[cfg(any(target_os = "android", target_os = "ios"))]
pub use mobile::TunDevice;

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "android",
    target_os = "ios"
)))]
mod pending;
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "android",
    target_os = "ios"
)))]
pub use pending::TunDevice;
