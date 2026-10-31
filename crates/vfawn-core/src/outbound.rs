// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Anti-loop policy for host-opened outbound sockets.
//!
//! Under the user-space stack the library never dials out itself; the
//! host does. Those sockets are at risk of being captured straight
//! back into the TUN device by the very routing rules the library
//! installed, which turns one outbound connection into an infinite
//! loop. The outbound hook is the escape hatch, and this module is
//! where a policy becomes a socket option.
//!
//! Why bind-to-device rather than a firewall exception: the capture is
//! policy routing (rules pointing at a dedicated table with the TUN as
//! default), and a socket bound to the physical interface constrains
//! route lookup to routes leaving that interface. The capture rules
//! stop matching and the main table takes over, so the escape needs no
//! per-socket rule bookkeeping and no exception list. The alternative
//! designs other stacks use, where a forwarder process owns every dial
//! and binds its own listener side, assume the stack and the dialer
//! live in different processes; here the host dials in-process, so the
//! hook travels to the host instead.
//!
//! Bindings are a snapshot taken at apply time: when the default
//! interface changes (cable to Wi-Fi), already-bound sockets keep their
//! old binding, and the host applies the hook again for new ones. The
//! interface name to bind comes from default-interface tracking at the
//! moment of the dial; this module takes it as a parameter and stays
//! free of platform code.

use crate::config::OutboundFdHook;
use std::io;
use std::os::fd::RawFd;

/// Apply the outbound policy to one socket.
///
/// `default_interface` is the name of the current default-route owner,
/// needed only by [`OutboundFdHook::BindDefaultIface`]; passing `None`
/// there is an [`io::ErrorKind::InvalidInput`] error rather than a
/// silent skip, because a socket that was supposed to escape the TUN
/// but silently did not is exactly the loop this hook exists to break.
///
/// On non-Linux Unix the bind variant reports
/// [`io::ErrorKind::Unsupported`]; the mobile equivalent is the host
/// callback variant, which works everywhere because the policy lives
/// in host code (see the enum documentation for the Android shape).
///
/// ```
/// use vfawn_core::{OutboundFdHook, outbound};
/// use std::io;
///
/// # fn jni_protect(_fd: std::os::fd::RawFd) -> io::Result<()> { Ok(()) }
/// // Android shape: the callback crosses into the JVM and calls
/// // VpnService.protect(fd) on a thread attached to it. The JNI call
/// // itself is host territory; this closure is the whole contract.
/// let hook = OutboundFdHook::HostCallback(std::sync::Arc::new(
///     move |fd| jni_protect(fd),
/// ));
/// // The no-op variant always succeeds and touches nothing.
/// assert!(outbound::apply(&OutboundFdHook::None, -1, None).is_ok());
/// ```
pub fn apply(hook: &OutboundFdHook, fd: RawFd, default_interface: Option<&str>) -> io::Result<()> {
    match hook {
        OutboundFdHook::None => Ok(()),
        OutboundFdHook::BindDefaultIface => bind_to_interface(fd, default_interface),
        OutboundFdHook::HostCallback(protect) => protect(fd),
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // adopting the caller's fd for one setsockopt
fn bind_to_interface(fd: RawFd, interface: Option<&str>) -> io::Result<()> {
    let Some(name) = interface else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no default interface is known; refusing to leave the socket unbound",
        ));
    };
    if fd < 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid fd"));
    }
    // SO_BINDTODEVICE expects a NUL-terminated interface name; the
    // option requires CAP_NET_RAW, which a VPN-shaped process holds.
    // Adopting the fd and forgetting the handle afterwards borrows it
    // for the call without closing what the caller still owns.
    // Safety: the caller passed a live socket fd it owns for the call,
    // and the forget below hands it back before anything can drop it.
    use std::os::fd::FromRawFd;
    let adopted = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let socket = socket2::SockRef::from(&adopted);
    let bound = socket.bind_device(Some(name.as_bytes()));
    std::mem::forget(adopted);
    bound
}

#[cfg(not(target_os = "linux"))]
fn bind_to_interface(_fd: RawFd, _interface: Option<&str>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_BINDTODEVICE is a Linux option; use the host callback variant here",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::RawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI32, Ordering};

    #[test]
    fn none_touches_nothing() {
        // A negative fd would fail any real syscall; success here
        // proves the variant never reaches one.
        assert!(apply(&OutboundFdHook::None, -1, None).is_ok());
    }

    #[test]
    fn host_callback_sees_the_fd_and_its_errors() {
        let seen = Arc::new(AtomicI32::new(-1));
        let recorder = {
            let seen = Arc::clone(&seen);
            move |fd: RawFd| -> io::Result<()> {
                seen.store(fd, Ordering::SeqCst);
                Ok(())
            }
        };
        assert!(apply(&OutboundFdHook::HostCallback(Arc::new(recorder)), 7, None).is_ok());
        assert_eq!(seen.load(Ordering::SeqCst), 7);

        let failing = |_: RawFd| -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        };
        let err = apply(&OutboundFdHook::HostCallback(Arc::new(failing)), 7, None)
            .expect_err("callback error must propagate");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn bind_without_a_known_interface_is_loud() {
        // Not a silent skip: the caller must learn the escape did not
        // happen. On non-Linux the same call reports Unsupported, which
        // this test also pins.
        let err = apply(&OutboundFdHook::BindDefaultIface, -1, None).expect_err("must fail");
        assert!(
            err.kind() == io::ErrorKind::InvalidInput || err.kind() == io::ErrorKind::Unsupported
        );
    }
}
