// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Darwin backend: utun device plumbing, PF_ROUTE socket for interface and
//! route manipulation, and the platform event feed.
//!
//! utun moves exactly one packet per syscall and offers no kernel offload, so
//! throughput work on this platform is about batching syscalls (recvmmsg /
//! sendmmsg) and keeping the pending-packet budget configured, not about
//! offload.
