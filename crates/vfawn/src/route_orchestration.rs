// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Route orchestration: the `auto_route` half of the configuration,
//! assembled into one installable unit.
//!
//! One flag in the host config turns into the whole Linux capture story:
//! the desired state built from the config, applied atomically by the
//! reconciler over rtnetlink, and then kept alive by the monitor and the
//! auto-reconciliation loop. Losing the network (default interface gone,
//! links flapping) heals itself; a rule deleted underneath us comes back
//! after the debounce window. Dropping the orchestration plans the
//! kernel back to empty, which is also what a clean shutdown wants.
//!
//! The DNS-leak policy rule from the route model needs a backend that
//! can express destination-port selectors; rtnetlink rules here cannot,
//! and the in-stack hijack already intercepts port-53 flows before the
//! kernel routes them, so the bootstrap passes the flag as off and
//! leaves kernel-level enforcement to hosts that wire the nftables
//! backend themselves.

use std::sync::Arc;
use std::sync::RwLock;
use vfawn_core::VfawnConfig;
#[cfg(target_os = "linux")]
use vfawn_platform::linux::{NetlinkBackend, NetworkMonitor};
#[cfg(target_os = "macos")]
use vfawn_platform::macos::{DarwinRouteBackend, NetworkMonitor};
#[cfg(target_os = "windows")]
use vfawn_platform::windows::{NetworkMonitor, WindowsRouteBackend};
use vfawn_route::{AutoReconciler, DesiredState, Reconciler, RouteParams, desired_from_config};

/// The installed capture: desired state, reconciler, and the self-heal
/// loop, all tied to one interface.
pub struct RouteOrchestration {
    reconciler: Arc<Reconciler>,
    desired: Arc<RwLock<DesiredState>>,
    auto: Option<AutoReconciler>,
    monitor: Option<NetworkMonitor>,
}

impl RouteOrchestration {
    /// Build the desired state from the config, apply it, and start
    /// watching the network.
    pub fn install(
        config: &VfawnConfig,
        interface: &str,
        addresses: &[ipnet::IpNet],
    ) -> Result<Self, std::io::Error> {
        let desired = desired_state_of(config, interface, addresses);
        #[cfg(target_os = "linux")]
        let backend = Arc::new(NetlinkBackend::new()?);
        #[cfg(target_os = "macos")]
        let backend = Arc::new(DarwinRouteBackend::new());
        #[cfg(target_os = "windows")]
        let backend = Arc::new(WindowsRouteBackend::new());
        let reconciler = Arc::new(Reconciler::new(backend));
        reconciler
            .apply(&desired)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let shared = Arc::new(RwLock::new(desired));
        let mut monitor = NetworkMonitor::start()?;
        // Taking the receiver starts nothing on its own; the loop below
        // is what drains it, and a monitor without a reader would drop
        // events on a full channel.
        let auto = AutoReconciler::start(
            Arc::clone(&shared),
            Arc::clone(&reconciler),
            monitor.events().expect("events taken once"),
        );
        Ok(Self {
            reconciler,
            desired: shared,
            auto: Some(auto),
            monitor: Some(monitor),
        })
    }

    /// Swap in a new desired state: applied once immediately, and the
    /// self-heal loop reconciles toward it from then on.
    pub fn update(
        &self,
        config: &VfawnConfig,
        interface: &str,
        addresses: &[ipnet::IpNet],
    ) -> Result<(), vfawn_route::ReconcileError> {
        let desired = desired_state_of(config, interface, addresses);
        *self.desired.write().expect("desired state lock poisoned") = desired.clone();
        self.reconciler.apply(&desired)
    }

    /// Plan the kernel back to empty. The order matters: the
    /// self-heal loop stops first, or it would race this teardown by
    /// re-installing what this removes.
    pub fn remove(&mut self) -> Result<(), vfawn_route::ReconcileError> {
        self.auto = None;
        self.monitor = None;
        // Empty by the same table and rule indices the capture used, so
        // the removal plan recognizes everything the install created.
        let (table_index, rule_index, interface_name) = {
            let current = self.desired.read().expect("desired state lock poisoned");
            (
                current.table_index,
                current.rule_index,
                current.interface_name.clone(),
            )
        };
        let empty = DesiredState {
            interface_name,
            addresses: Vec::new(),
            routes: Vec::new(),
            rules: Vec::new(),
            excluded: Vec::new(),
            table_index,
            rule_index,
        };
        *self.desired.write().expect("desired state lock poisoned") = empty.clone();
        self.reconciler.apply(&empty)
    }
}

impl Drop for RouteOrchestration {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

fn desired_state_of(
    config: &VfawnConfig,
    interface: &str,
    addresses: &[ipnet::IpNet],
) -> DesiredState {
    desired_from_config(&RouteParams {
        interface,
        addresses,
        captured: &config.route.route_address,
        excluded: &config.route.route_exclude_address,
        table_index: config.route.table_index,
        rule_index: config.route.rule_index,
        mark: config.route.mark,
        bypass_mark: redirect_marks_of(config).0,
        capture_mark: redirect_marks_of(config).1,
        strict_route: config.route.strict_route,
        dns_leak_prevention: false,
        include_uid: &config.route.include_uid,
        exclude_uid: &config.route.exclude_uid,
    })
}

/// The pre-match marks the policy rules honor, `(bypass, capture)`:
/// the configured ones when the per-flow bypass is on, zero (no rule)
/// otherwise.
pub(crate) fn redirect_marks_of(config: &VfawnConfig) -> (u32, u32) {
    let redirect = &config.route.auto_redirect;
    if redirect.enabled {
        (redirect.output_mark, redirect.input_mark)
    } else {
        (0, 0)
    }
}

/// Install the per-flow kernel bypass when the configuration asks for
/// it. A host without the queue modules, the nft binary or the
/// privilege keeps running on the plain capture: every flow then takes
/// the device path, which is correct, only slower for bypassed flows.
#[cfg(target_os = "linux")]
pub(crate) fn install_auto_redirect(
    config: &VfawnConfig,
    interface: &str,
    addresses: &[ipnet::IpNet],
    handler: Arc<dyn vfawn_core::SessionHandler>,
) -> Option<vfawn_platform::linux::AutoRedirect> {
    use vfawn_platform::linux::{AutoRedirect, RedirectParams, auto_redirect};

    let redirect = &config.route.auto_redirect;
    if !redirect.enabled {
        return None;
    }
    let mut excluded = DesiredState::default_exclusions();
    excluded.extend_from_slice(&config.route.route_exclude_address);
    let params = RedirectParams {
        interface,
        tun_addresses: addresses,
        captured: &config.route.route_address,
        excluded: &excluded,
        escape_mark: config.route.mark,
        dns_hijack: config.dns.mode == vfawn_core::DnsMode::Hijack,
        input_mark: redirect.input_mark,
        output_mark: redirect.output_mark,
        reset_mark: redirect.reset_mark,
        queue: redirect.queue,
    };
    match AutoRedirect::install(&params, handler) {
        Ok(installed) => {
            if let Some(egress) = vfawn_platform::linux::default_if::current_default_interface()
                && let Some(warning) = auto_redirect::rp_filter_warning(&egress.name)
            {
                eprintln!("vfawn: auto_redirect: {warning}");
            }
            Some(installed)
        }
        Err(e) => {
            eprintln!("vfawn: auto_redirect unavailable, every flow takes the device path ({e})");
            None
        }
    }
}
