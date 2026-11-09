// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Linux backend: nftables rules, rtnetlink addresses and routes, and the
//! netlink event feed that drives route reconciliation.

pub mod anti_loop;
pub mod auto_redirect;
pub mod default_if;
pub mod docker_firewall;
pub mod monitor;
pub mod netlink;
pub mod nftables;
pub mod openwrt_firewall;
pub mod orphan;

pub use anti_loop::protect;
pub use auto_redirect::{AutoRedirect, Marks, RedirectParams};
pub use monitor::NetworkMonitor;
pub use netlink::NetlinkBackend;
pub use nftables::NftablesBackend;
pub use orphan::{CleanupReport, cleanup_nftables, ssh_session_sources};
