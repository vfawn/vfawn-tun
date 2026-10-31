// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The `up` command: create a TUN, terminate sessions through the stack,
//! echo everything back.

use std::sync::Arc;
use vfawn::echo::VerboseEchoHandler;
use vfawn::{Instance, VfawnConfig};

/// Bring up a TUN device and echo every session to stdout.
///
/// The device gets the first argument as its IPv4 address (prefix
/// included); the second argument overrides the MTU. Runs until the caller
/// stops it, which `main` wires to SIGINT and SIGTERM.
pub fn run(
    address: &str,
    mtu: u32,
    bind_default_iface: bool,
    relay: bool,
    auto_route: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let prefix: ipnet::Ipv4Net = address.parse()?;

    let mut config = VfawnConfig::default();
    config.device.mtu = mtu;
    config.device.inet4_address = vec![prefix];
    config.route.auto_route = auto_route;
    if bind_default_iface {
        // Only the policy is set here; sockets the host opens while the
        // instance runs read the flag from the config and bind to the
        // default interface at dial time.
        config.stack.outbound_fd_hook = vfawn_core::OutboundFdHook::BindDefaultIface;
    }

    // The relay is the bench seat: sessions dial their original
    // destinations and escape the capture through the outbound hook.
    let handler: Arc<dyn vfawn_core::SessionHandler> = if relay {
        let protect: vfawn::Protect = std::sync::Arc::new(|fd| {
            #[cfg(target_os = "linux")]
            {
                vfawn_platform::linux::protect(&vfawn_core::OutboundFdHook::BindDefaultIface, fd)
                    .map(|_| ())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = fd;
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "relay escape needs the Linux bind hook",
                ))
            }
        });
        Arc::new(vfawn::RelayHandler::new(Some(protect)))
    } else {
        Arc::new(VerboseEchoHandler::new())
    };
    println!("creating TUN device with {} mtu={} ...", address, mtu);

    let mut instance = Instance::new(config, handler.clone())?;
    instance.start(handler)?;

    println!("ready; sessions will appear below; Ctrl-C to stop");

    // Block until the caller tells us to stop. The signal handling lives
    // in `main`, which calls `stop` on this thread's control channel.
    // For now, park this thread; main sends the wake.
    std::thread::park();

    println!("shutting down ...");
    instance.shutdown()?;
    println!("device closed");
    Ok(())
}
