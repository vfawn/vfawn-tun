// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Windows backend: wintun device access, iphlpapi for interfaces and routes,
//! and firewall rules through the INetFwPolicy2 COM interface.

pub mod anti_loop;
pub mod default_if;
pub mod firewall;
pub mod monitor;
pub mod route_backend;

pub use anti_loop::protect;
pub use default_if::{DefaultInterface, current_default_interface};
pub use firewall::{
    apply as firewall_apply, documented_add as firewall_documented_add, remove as firewall_remove,
    rule_name as firewall_rule_name,
};
pub use monitor::NetworkMonitor;
pub use route_backend::WindowsRouteBackend;
