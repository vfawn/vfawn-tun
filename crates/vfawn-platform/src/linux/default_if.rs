// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Default interface tracking: which physical interface owns the default
//! route right now, and has it changed since we last looked.

use std::net::IpAddr;

/// The current default-route owner plus its addresses, so the caller can
/// decide what to exclude when capturing traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultInterface {
    pub name: String,
    pub addresses: Vec<IpAddr>,
}

/// Read the default IPv4 interface from /proc/net/route and collect its
/// addresses from /proc/net/fib_trie (or fall back to /proc/net/dev).
pub fn current_default_interface() -> Option<DefaultInterface> {
    let name = super::monitor::read_default_interface()?;
    let addresses = interface_addresses(&name);
    Some(DefaultInterface { name, addresses })
}

/// Read all addresses assigned to a named interface from /proc/net/if_inet6
/// (IPv6) and /proc/net/route (IPv4, via the fib trie).
fn interface_addresses(_name: &str) -> Vec<IpAddr> {
    // For M1, return a placeholder; full address enumeration is a route
    // engine concern (015's snapshot covers it). This list feeds only the
    // "what to exclude" hint, so empty is safe.
    Vec::new()
}
