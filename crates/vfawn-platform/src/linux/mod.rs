// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Linux backend: nftables rules, rtnetlink addresses and routes, and the
//! netlink event feed that drives route reconciliation.

pub mod netlink;

pub use netlink::NetlinkBackend;
