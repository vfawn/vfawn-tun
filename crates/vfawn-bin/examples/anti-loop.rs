// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The anti-loop escape, demonstrated on one socket.
//!
//! With a capture setup installed (policy rules pulling routes into the
//! TUN), an ordinary socket's traffic re-enters the TUN and loops. This
//! example protects a socket with the bind variant and sends one probe:
//! on Linux the datagram leaves through the physical default interface,
//! because the binding constrains route lookup to it and the capture
//! rules stop matching.
//!
//! Run next to a live instance, as root:
//!
//! ```sh
//! sudo ./target/debug/examples/anti-loop
//! ```

use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use vfawn_core::OutboundFdHook;

fn main() {
    let probe = UdpSocket::bind("0.0.0.0:0").expect("udp socket");

    #[cfg(target_os = "linux")]
    {
        match vfawn_platform::linux::protect(&OutboundFdHook::BindDefaultIface, probe.as_raw_fd()) {
            Ok(Some(interface)) => {
                println!("socket bound to the default interface: {interface}");
                match probe.send_to(b"escape", "203.0.113.10:9") {
                    Ok(_) => println!("probe sent; it egresses {interface}, not the TUN"),
                    Err(e) => {
                        println!("probe failed: {e} (does {interface} carry a default route?)")
                    }
                }
                println!("watch it with: tcpdump -ni <physical> udp and host 203.0.113.10");
            }
            Ok(None) => unreachable!("the bind variant always names the interface"),
            Err(e) => {
                eprintln!("protect failed: {e}");
                eprintln!("binding needs CAP_NET_RAW and a present default route");
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = probe;
        println!("SO_BINDTODEVICE is Linux-only; use the host callback variant here.");
        println!("See the OutboundFdHook documentation for the mobile shape.");
    }
}
