// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! TUN device access, uniform across platforms.
//!
//! Wraps tun-rs and exposes creation, configuration, batched reads and
//! writes, and capability reporting (offload support, queue count) through
//! the `PacketDevice` contract. Batched I/O is the core abstraction: per-packet
//! syscalls are the first throughput ceiling on any TUN-backed data path.
//!
//! This crate carries no packet semantics of its own; anything that has to
//! understand a header belongs in `vfawn-wire` or the stacks.
