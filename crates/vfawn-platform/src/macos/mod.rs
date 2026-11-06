// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Darwin backend: utun device plumbing, the route command as the
//! route backend, and the platform event feed.
//!
//! utun moves exactly one packet per syscall and offers no kernel
//! offload, so throughput work on this platform is about batching
//! syscalls (recvmmsg / sendmmsg / `UTUN_OPT_MAX_PENDING_PACKETS`
//! 攒包 — sing-tun darwin 实证三板斧) and keeping the
//! pending-packet budget configured, not about offload. The route
//! backend wraps the system's `route` command for v0; the PF_ROUTE
//! socket replaces it when the reconciliation cadence makes the
//! process-spawn overhead visible.

pub mod route_backend;

pub use route_backend::DarwinRouteBackend;

pub mod monitor;

pub use monitor::NetworkMonitor;
