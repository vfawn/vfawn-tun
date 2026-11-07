// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Platform glue, one crate for all targets.
//!
//! Rule backends, interface and address manipulation, and the network event
//! feed live behind compile-time module selection, mirroring how the layers
//! are actually mutual: a Linux build never needs the Darwin or Windows code,
//! and vice versa. Code shared across Unix systems (fd handling, interface
//! binding) sits in the `unix` module rather than being duplicated per OS.
//!
//! Mobile targets ride the Linux path: Android is the Linux kernel with a
//! host-supplied fd, and the bindings layer carries the Java/Swift side.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(unix)]
pub mod unix;
#[cfg(target_os = "windows")]
pub mod windows;

/// The Windows firewall posture for this process's executable,
/// inert everywhere else. Returns the rule's name when one is (or
/// will be) in effect.
#[cfg(target_os = "windows")]
pub fn firewall_gate(mode: vfawn_core::WindowsFirewallMode) -> std::io::Result<Option<String>> {
    windows::firewall::apply(mode)
}

/// Remove this process's firewall rule; inert everywhere else and
/// idempotent on Windows.
#[cfg(target_os = "windows")]
pub fn firewall_gate_remove() -> std::io::Result<()> {
    windows::firewall::remove()
}

#[cfg(not(target_os = "windows"))]
pub fn firewall_gate(_mode: vfawn_core::WindowsFirewallMode) -> std::io::Result<Option<String>> {
    Ok(None)
}

#[cfg(not(target_os = "windows"))]
pub fn firewall_gate_remove() -> std::io::Result<()> {
    Ok(())
}
