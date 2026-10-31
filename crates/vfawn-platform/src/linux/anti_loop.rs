// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The Linux anti-loop wiring: resolve the default interface, apply the
//! hook.
//!
//! [`vfawn_core::outbound::apply`] is pure policy over an interface
//! name; this module is where the name comes from. Reading the default
//! route at apply time is what makes the binding a snapshot of the
//! network as it is right now: after a change of default interface,
//! already-bound sockets keep the old name (the kernel holds the
//! binding) and sockets the host opens afterwards pick up the new one
//! without any migration step.

use std::io;
use std::os::fd::RawFd;
use vfawn_core::OutboundFdHook;

/// Apply the hook to `fd`, resolving the current default interface for
/// the bind variant.
///
/// Returns the interface name that was bound, so callers can log it or
/// compare it against the previous dial's snapshot.
pub fn protect(hook: &OutboundFdHook, fd: RawFd) -> io::Result<Option<String>> {
    match hook {
        OutboundFdHook::None => {
            vfawn_core::outbound::apply(hook, fd, None)?;
            Ok(None)
        }
        OutboundFdHook::BindDefaultIface => {
            let interface = crate::linux::default_if::current_default_interface()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "no default interface; nothing to bind to",
                    )
                })?
                .name;
            vfawn_core::outbound::apply(hook, fd, Some(&interface))?;
            Ok(Some(interface))
        }
        OutboundFdHook::HostCallback(_) => {
            vfawn_core::outbound::apply(hook, fd, None)?;
            Ok(None)
        }
    }
}
