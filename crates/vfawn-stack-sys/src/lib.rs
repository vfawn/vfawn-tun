// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Kernel-side termination.
//!
//! Instead of terminating TCP in user space, packets are rewritten onto a
//! secondary address of the TUN interface and written back, letting the OS
//! stack deliver them to ordinary local listeners; the return path applies
//! the inverse rewrite from the NAT table. TCP semantics (SACK, ECN,
//! congestion control) stay with the kernel, which is where this backend gets
//! its correctness and throughput ceiling.
