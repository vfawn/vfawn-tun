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

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::TunDevice;

#[cfg(not(target_os = "linux"))]
mod pending;
#[cfg(not(target_os = "linux"))]
pub use pending::TunDevice;
