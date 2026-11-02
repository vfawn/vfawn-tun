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
    stack_native: bool,
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

    if stack_native {
        run_native(config, handler, auto_route)
    } else {
        run_ipstack(config, handler)
    }
}

/// The default path: the facade instance with the transitional backend.
fn run_ipstack(
    config: VfawnConfig,
    handler: Arc<dyn vfawn_core::SessionHandler>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

/// The in-house stack bench seat: same device, same capture
/// orchestration, same handler, one backend swapped. The facade's
/// per-flow policy picks backends itself later; until then the A/B
/// comparison rides this direct path.
fn run_native(
    config: VfawnConfig,
    handler: Arc<dyn vfawn_core::SessionHandler>,
    auto_route: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let device = vfawn_device::TunDevice::create(&config.device)?;
    #[cfg(not(target_os = "linux"))]
    let _ = auto_route;

    // Capture before traffic flows, exactly as the facade orders it:
    // the rules reference the device's real name.
    #[cfg(target_os = "linux")]
    let mut orchestration = None;
    #[cfg(target_os = "linux")]
    if auto_route {
        let interface = device.name()?;
        let addresses: Vec<ipnet::IpNet> = config
            .device
            .inet4_address
            .iter()
            .map(|n| (*n).into())
            .chain(config.device.inet6_address.iter().map(|n| (*n).into()))
            .collect();
        orchestration = Some(vfawn::route_orchestration::RouteOrchestration::install(
            &config, &interface, &addresses,
        )?);
    }

    let mss = (config.device.mtu.min(65535) as u16)
        .saturating_sub(40)
        .max(536);
    let backend = Box::new(vfawn_stack_user::NativeBackend {
        congestion: config.stack.congestion,
        mss,
        ..vfawn_stack_user::NativeBackend::default()
    });
    let _handle = vfawn_core::StackBackend::spawn(backend, Box::new(device), handler)?;

    println!("ready; sessions will appear below; Ctrl-C to stop");
    std::thread::park();

    println!("shutting down ...");
    // The backend's threads live for the process; the capture rules
    // must not outlive an orderly stop. Off Linux there was nothing
    // to install.
    #[cfg(target_os = "linux")]
    if let Some(mut orchestration) = orchestration {
        let _ = orchestration.remove();
    }
    println!("device closed");
    Ok(())
}
