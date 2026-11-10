// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The Windows anti-loop wiring: the escape sing-box runs on this
//! platform, a socket bound to the default interface by index
//! (sing's `control.BindToInterface`, `common/control/bind_windows.go`).
//! Windows has no routing mark; `IP_UNICAST_IF` constrains the route
//! lookup to routes leaving the named interface, so the capture's
//! default route through the TUN stops matching.
//!
//! The binding is a snapshot of the default interface at dial time,
//! the same contract the Linux bind holds.

use std::io;
use std::os::windows::io::RawSocket;
use vfawn_core::OutboundFdHook;
use windows_sys::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, WSAGetLastError,
    setsockopt,
};

use crate::windows::default_if::current_default_interface;

/// Apply the hook to `socket`, resolving the current default interface
/// for the bind variant. Returns the interface name that was bound.
pub fn protect(hook: &OutboundFdHook, socket: RawSocket) -> io::Result<Option<String>> {
    match hook {
        OutboundFdHook::BindDefaultIface => {
            let interface = current_default_interface()?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no default interface; nothing to bind to",
                )
            })?;
            bind_to_interface(socket, interface.index)?;
            Ok(Some(interface.name))
        }
        OutboundFdHook::None | OutboundFdHook::Mark(_) | OutboundFdHook::HostCallback(_) => {
            vfawn_core::outbound::apply(hook, socket, None)?;
            Ok(None)
        }
    }
}

/// Bind both families, as sing does when the dial address is not yet
/// known: `IP_UNICAST_IF` fails with WSAEINVAL on a v6-only socket and
/// `IPV6_UNICAST_IF` with WSAEADDRNOTAVAIL on an AF_INET one, so one
/// success is the binding and only two failures are an error.
fn bind_to_interface(socket: RawSocket, index: u32) -> io::Result<()> {
    // IP_UNICAST_IF takes the index in network byte order;
    // IPV6_UNICAST_IF takes it in host order.
    let v4 = set_option(socket, IPPROTO_IP, IP_UNICAST_IF, index.to_be());
    let v6 = set_option(socket, IPPROTO_IPV6, IPV6_UNICAST_IF, index);
    match (v4, v6) {
        (Err(v4), Err(v6)) => Err(io::Error::new(
            v4.kind(),
            format!("bind to interface {index}: IP_UNICAST_IF: {v4}; IPV6_UNICAST_IF: {v6}"),
        )),
        _ => Ok(()),
    }
}

#[expect(unsafe_code)]
fn set_option(socket: RawSocket, level: i32, name: i32, value: u32) -> io::Result<()> {
    // SAFETY: setsockopt reads four bytes from a live local; the socket
    // belongs to the caller and stays open through the call.
    let result = unsafe {
        setsockopt(
            socket as usize,
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as i32,
        )
    };
    if result == SOCKET_ERROR {
        // SAFETY: reads the calling thread's last socket error.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}
