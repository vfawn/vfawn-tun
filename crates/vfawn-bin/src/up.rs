// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The `up` command: create a TUN, terminate sessions through the stack,
//! echo everything back.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use vfawn::echo::VerboseEchoHandler;
use vfawn::{Instance, VfawnConfig};

/// Raised by `main` on SIGINT or SIGTERM, before it unparks the worker.
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Ask a running `up` to shut down; the caller unparks its thread.
pub fn request_stop() {
    STOP_REQUESTED.store(true, Ordering::Release);
}

/// Park until the caller asks to stop (`Ok`) or the stack stops on its
/// own (`Err` with the reason). A lost device is not rebuilt, as
/// sing-tun's stack does not rebuild it: the process exits with an
/// error and whatever supervises it decides on a restart.
fn wait_for_stop(failure: impl Fn() -> Option<String>) -> Result<(), String> {
    loop {
        if let Some(reason) = failure() {
            return Err(reason);
        }
        if STOP_REQUESTED.load(Ordering::Acquire) {
            return Ok(());
        }
        std::thread::park_timeout(Duration::from_millis(200));
    }
}

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
    // The escape comes with the capture it answers for: auto-route's
    // table carries a default, so the process's own dials need a way
    // past it. The mark is the standing answer — the same shape
    // WireGuard and sing-box run, surviving default-interface changes
    // a binding cannot. The binding stays as the explicit override:
    // a socket bound to the physical interface answers the oif
    // constraint directly, which is the belt to the mark's braces.
    // Windows has no routing mark: the binding is the whole escape
    // there, as sing-box runs it (IP_UNICAST_IF to the default
    // interface).
    config.stack.outbound_fd_hook = if bind_default_iface || (auto_route && cfg!(windows)) {
        vfawn_core::OutboundFdHook::BindDefaultIface
    } else if auto_route {
        vfawn_core::OutboundFdHook::Mark(config.route.mark)
    } else {
        vfawn_core::OutboundFdHook::None
    };

    // The relay is the bench seat: sessions dial their original
    // destinations and escape the capture through the outbound hook.
    let handler: Arc<dyn vfawn_core::SessionHandler> = if relay {
        // The hook binding only exists where the escape compiles; the
        // other platforms refuse the dial rather than loop it back.
        #[cfg(any(target_os = "linux", windows))]
        let hook = config.stack.outbound_fd_hook.clone();
        let protect: vfawn::Protect = std::sync::Arc::new(move |fd| {
            #[cfg(target_os = "linux")]
            {
                vfawn_platform::linux::protect(&hook, fd).map(|_| ())
            }
            #[cfg(windows)]
            {
                vfawn_platform::windows::protect(&hook, fd).map(|_| ())
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                let _ = fd;
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "relay escape needs the Linux or Windows hook",
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

    // Block until `main` relays a stop signal or the stack stops on its own.
    let outcome = wait_for_stop(|| instance.failure());

    println!("shutting down ...");
    instance.shutdown()?;
    println!("device closed");
    outcome.map_err(|reason| format!("device lost: {reason}").into())
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

    // Capture before traffic flows, exactly as the facade orders it
    // (`Instance::finish_start`): the rules reference the device's
    // real name. No firewall rule: the native stack reads the device
    // and never accepts on a socket, and sing-tun takes its inbound
    // rule only for the system stack, which does (stack_system.go:145).
    let mut orchestration = None;
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
        broadcast: config
            .device
            .inet4_address
            .first()
            .map(ipnet::Ipv4Net::broadcast),
        ..vfawn_stack_user::NativeBackend::default()
    });
    let handle = vfawn_core::StackBackend::spawn(backend, Box::new(device), handler)?;

    println!("ready; sessions will appear below; Ctrl-C to stop");
    let outcome = wait_for_stop(|| handle.failure());

    println!("shutting down ...");
    // The backend's threads live for the process; the capture rules
    // must not outlive an orderly stop.
    if let Some(mut orchestration) = orchestration {
        let _ = orchestration.remove();
    }
    println!("device closed");
    outcome.map_err(|reason| format!("device lost: {reason}").into())
}
