// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Root-only checks of the bind variant against the real kernel: the
//! option lands on the socket, and the interface name comes from the
//! host's live routing table.
//!
//! ```sh
//! sudo -E cargo test -p vfawn-platform --test anti_loop_root -- --ignored --nocapture
//! ```
//!
//! The full loop-and-escape story, with packets asserted on interfaces,
//! lives in `anti_loop_netns.rs`; these tests pin the mechanism.

#![cfg(target_os = "linux")]

use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use vfawn_core::OutboundFdHook;
use vfawn_platform::linux::{default_if::current_default_interface, protect};

/// Read SO_BINDTODEVICE back off a socket; the empty string means
/// unbound. Only root can set the option, but anyone can read it.
fn bound_device(fd: std::os::fd::RawFd) -> String {
    let mut name = [0u8; 16];
    let mut len = name.len() as u32;
    // Safety: a fixed-size buffer with its length passed alongside.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_mut_ptr().cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt SO_BINDTODEVICE");
    let n = name.iter().position(|&b| b == 0).unwrap_or(len as usize);
    String::from_utf8_lossy(&name[..n]).into_owned()
}

#[test]
#[ignore]
fn protect_binds_the_socket_to_the_default_interface() {
    let default = current_default_interface().expect("host has a default route");
    let socket = UdpSocket::bind("0.0.0.0:0").expect("udp socket");
    assert_eq!(
        bound_device(socket.as_raw_fd()),
        "",
        "fresh socket is unbound"
    );

    let bound =
        protect(&OutboundFdHook::BindDefaultIface, socket.as_raw_fd()).expect("apply the hook");
    assert_eq!(bound.as_deref(), Some(default.name.as_str()));
    assert_eq!(bound_device(socket.as_raw_fd()), default.name);
}

#[test]
#[ignore]
fn each_dial_takes_a_fresh_snapshot_of_the_default() {
    // Two calls, two sockets: both resolve the default interface at
    // their own dial time. Nothing migrates an existing binding, which
    // the second readback pins: it still names whatever was current
    // when that socket was protected, not something later.
    let default = current_default_interface().expect("host has a default route");
    let first = UdpSocket::bind("0.0.0.0:0").expect("first socket");
    let second = UdpSocket::bind("0.0.0.0:0").expect("second socket");

    protect(&OutboundFdHook::BindDefaultIface, first.as_raw_fd()).expect("first apply");
    protect(&OutboundFdHook::BindDefaultIface, second.as_raw_fd()).expect("second apply");

    assert_eq!(bound_device(first.as_raw_fd()), default.name);
    assert_eq!(bound_device(second.as_raw_fd()), default.name);

    // Re-protecting the first socket after the fact rebinds it to the
    // current snapshot: the escape stays fresh if the host reapplies.
    protect(&OutboundFdHook::BindDefaultIface, first.as_raw_fd()).expect("re-apply");
    let now = current_default_interface().expect("default still present");
    assert_eq!(bound_device(first.as_raw_fd()), now.name);
}

#[test]
#[ignore]
fn host_callback_variant_passes_the_fd_through() {
    use std::sync::Arc;
    let seen = Arc::new(std::sync::atomic::AtomicI32::new(-1));
    let recorder = {
        let seen = Arc::clone(&seen);
        move |fd: std::os::fd::RawFd| -> std::io::Result<()> {
            seen.store(fd, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    };
    let socket = UdpSocket::bind("0.0.0.0:0").expect("udp socket");
    let hook = OutboundFdHook::HostCallback(Arc::new(recorder));
    protect(&hook, socket.as_raw_fd()).expect("callback path");
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::SeqCst),
        socket.as_raw_fd()
    );
}
