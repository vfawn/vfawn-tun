// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Live checks of the Windows bind variant: the default interface is
//! read off the host's routing table, and the option lands on the
//! socket in each family's own byte order. IP_UNICAST_IF needs no
//! elevation; the tests are ignored only because they read the live
//! network.
//!
//! ```powershell
//! cargo test -p vfawn-platform --test anti_loop_windows -- --ignored --nocapture
//! ```

#![cfg(target_os = "windows")]

use std::net::UdpSocket;
use std::os::windows::io::{AsRawSocket, RawSocket};
use vfawn_core::OutboundFdHook;
use vfawn_platform::windows::{current_default_interface, protect};
use windows_sys::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, getsockopt,
};

/// Read a four-byte socket option back; zero means unbound.
fn read_option(socket: RawSocket, level: i32, name: i32) -> u32 {
    let mut value = 0u32;
    let mut len = std::mem::size_of_val(&value) as i32;
    // SAFETY: a four-byte local with its length passed alongside.
    #[allow(unsafe_code)]
    let rc = unsafe {
        getsockopt(
            socket as usize,
            level,
            name,
            std::ptr::from_mut(&mut value).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt level={level} name={name}");
    value
}

#[test]
#[ignore]
fn the_default_interface_is_a_real_way_out() {
    let default = current_default_interface()
        .expect("read the route table")
        .expect("the host has a default route");
    println!(
        "default interface: {} (index {})",
        default.name, default.index
    );
    assert_ne!(default.index, 0);
}

#[test]
#[ignore]
fn protect_binds_a_v4_socket_in_network_order() {
    let default = current_default_interface().unwrap().expect("default route");
    let socket = UdpSocket::bind("0.0.0.0:0").expect("udp socket");
    let raw = socket.as_raw_socket();
    assert_eq!(
        read_option(raw, IPPROTO_IP, IP_UNICAST_IF),
        0,
        "fresh socket is unbound"
    );

    let bound = protect(&OutboundFdHook::BindDefaultIface, raw).expect("apply the hook");
    assert_eq!(bound.as_deref(), Some(default.name.as_str()));
    assert_eq!(
        read_option(raw, IPPROTO_IP, IP_UNICAST_IF),
        default.index.to_be()
    );
}

#[test]
#[ignore]
fn protect_binds_a_v6_socket_in_host_order() {
    let default = current_default_interface().unwrap().expect("default route");
    let Ok(socket) = UdpSocket::bind("[::]:0") else {
        println!("skip: IPv6 is disabled on this host");
        return;
    };
    let raw = socket.as_raw_socket();
    protect(&OutboundFdHook::BindDefaultIface, raw).expect("apply the hook");
    assert_eq!(
        read_option(raw, IPPROTO_IPV6, IPV6_UNICAST_IF),
        default.index
    );
}

#[test]
#[ignore]
fn the_mark_is_refused_rather_than_skipped() {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("udp socket");
    let refused = protect(&OutboundFdHook::Mark(0x2023), socket.as_raw_socket())
        .expect_err("Windows has no routing mark");
    assert_eq!(refused.kind(), std::io::ErrorKind::Unsupported);
}
