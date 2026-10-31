// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Linux backend: nftables rules, rtnetlink addresses and routes, and the
//! netlink event feed that drives route reconciliation.

pub mod anti_loop;
pub mod default_if;
pub mod monitor;
pub mod netlink;
pub mod nftables;
pub mod orphan;

pub use anti_loop::protect;
pub use monitor::NetworkMonitor;
pub use netlink::NetlinkBackend;
pub use nftables::NftablesBackend;
pub use orphan::{CleanupReport, cleanup_nftables, ssh_session_sources};
