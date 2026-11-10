// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Instance lifecycle: compose a device, a backend and the host handler
//! into one runnable unit.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use vfawn_core::{SessionHandler, StackHandle, VfawnConfig};
use vfawn_route::Reconciler;

/// Why a reconfiguration cannot proceed right now.
#[derive(Debug)]
#[non_exhaustive]
pub enum RestartReason {
    /// The requested change requires recreating the device or the stack
    /// backend; the caller should build a new [`Instance`] instead.
    NeedsRestart,
}

impl std::fmt::Display for RestartReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedsRestart => f.write_str("this change requires a restart"),
        }
    }
}

impl std::error::Error for RestartReason {}

/// A snapshot of instance-level counters. The fields grow as observability
/// lands; the type is here from day one so the host-facing API is stable.
#[derive(Debug, Clone, Default)]
pub struct StatsSnapshot {
    pub sessions_total: u64,
    pub bytes_forward: u64,
    pub bytes_reverse: u64,
    /// Data-plane panics caught and contained; zero is the norm.
    pub panics_contained: u64,
}

/// How long `shutdown` waits for in-flight sessions to complete before
/// tearing down anyway. Embedded hosts care about shutdown latency.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// A handle onto the running instance.
///
/// Constructing an [`Instance`] creates the device and prepares the stack;
/// [`Instance::start`] wires the handler and begins terminating traffic;
/// [`Instance::shutdown`] drains sessions and closes the device.
///
/// Route orchestration (the `auto_route` half of the configuration) is the
/// route engine's job and is not driven from here yet.
pub struct Instance {
    config: VfawnConfig,
    handle: Option<StackHandle>,
    panics: Arc<AtomicU64>,
    reconciler: Option<Reconciler>,
    /// The per-flow kernel bypass. Declared ahead of the orchestration
    /// so a drop removes its rules before the routes they lean on.
    #[cfg(target_os = "linux")]
    auto_redirect: Option<vfawn_platform::linux::AutoRedirect>,
    orchestration: Option<crate::route_orchestration::RouteOrchestration>,
    /// The firewall posture taken at start, for the symmetric removal
    /// at shutdown. None when nothing was taken.
    firewall_rule: Option<String>,
    /// The instance's own session accounting, attached to every flow
    /// the wrapper handler accepts.
    tracker: Arc<crate::stats::InstanceTracker>,
}

impl Instance {
    /// Validate the configuration and prepare the device.
    ///
    /// The handler is stored but not invoked until [`Instance::start`].
    /// On platforms without a device backend this returns an error from
    /// the device layer.
    pub fn new(
        config: VfawnConfig,
        handler: Arc<dyn SessionHandler>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        config.validate()?;
        let _ = handler;
        Ok(Instance {
            config,
            handle: None,
            panics: Arc::new(AtomicU64::new(0)),
            reconciler: None,
            #[cfg(target_os = "linux")]
            auto_redirect: None,
            orchestration: None,
            firewall_rule: None,
            tracker: Arc::new(crate::stats::InstanceTracker::new()),
        })
    }

    /// Begin terminating traffic.
    ///
    /// Creates the device from the configuration, spawns the backend, and
    /// hands every session to the handler. Blocks until the backend is
    /// running on its own threads.
    #[allow(unused_variables)]
    pub fn start(&mut self, handler: Arc<dyn SessionHandler>) -> io::Result<()> {
        if self.handle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "instance is already running",
            ));
        }
        // The instance counts every session through the same tracker
        // pipe a host's own counting rides; the host handler is
        // untouched below the wrapper.
        let counted = Arc::new(crate::stats::StatsHandler::new(
            handler,
            Arc::clone(&self.tracker),
        ));
        self.start_inner(counted)
    }

    fn start_inner(&mut self, handler: Arc<dyn SessionHandler>) -> io::Result<()> {
        // The host's own descriptor, when it supplies one: a network
        // extension or a supervisor that created the interface itself
        // hands over the fd instead of letting this process open a
        // second one. The framing contract (raw IP, no packet
        // information, no offload headers) is the host's to uphold.
        let device = match self.config.device.file_descriptor {
            #[cfg(unix)]
            Some(fd) => {
                // SAFETY: the configuration names a descriptor the
                // host owns and intends to hand over; adoption takes
                // its ownership for the instance's lifetime.
                #[expect(unsafe_code)]
                unsafe {
                    vfawn_device::TunDevice::from_fd(fd)?
                }
            }
            _ => vfawn_device::TunDevice::create(&self.config.device)?,
        };

        // The policy resolves before the first packet: Auto consults
        // its matrix (platform, capture mode, kernel-path facts), the
        // explicit policies answer themselves. An engine the build
        // left out falls back to the one that is in, with the choice
        // recorded so the mismatch is visible, not silent.
        let facts = vfawn_core::AutoFacts {
            platform: self.platform(),
            include_all_networks: self.config.stack.include_all_networks,
            kernel_path_available: cfg!(any(target_os = "linux", target_os = "macos")),
        };
        let choice = self.config.stack.policy.resolve(&facts);
        let backend: Box<dyn vfawn_core::StackBackend> = match choice {
            vfawn_core::AutoChoice::Userspace => self.native_backend(),
            vfawn_core::AutoChoice::Kernel => self.ipstack_backend(),
        };
        self.finish_start(backend, device, handler)
    }

    /// The platform fact the matrix consults.
    fn platform(&self) -> vfawn_core::Platform {
        #[cfg(target_os = "linux")]
        {
            vfawn_core::Platform::Linux
        }
        #[cfg(target_os = "macos")]
        {
            vfawn_core::Platform::Darwin
        }
        #[cfg(target_os = "windows")]
        {
            vfawn_core::Platform::Windows
        }
        #[cfg(target_os = "android")]
        {
            vfawn_core::Platform::Android
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "android"
        )))]
        {
            vfawn_core::Platform::Linux
        }
    }

    #[cfg(feature = "backend-native")]
    fn native_backend(&self) -> Box<dyn vfawn_core::StackBackend> {
        Box::new(vfawn_stack_user::NativeBackend {
            congestion: self.config.stack.congestion,
            broadcast: self.broadcast(),
            ..vfawn_stack_user::NativeBackend::default()
        })
    }

    #[cfg(not(feature = "backend-native"))]
    fn native_backend(&self) -> Box<dyn vfawn_core::StackBackend> {
        // The matrix chose userspace and the build has only the other
        // engine: the fallback is the transitional stack, and the
        // mismatch rides in the logs once, not in silence.
        eprintln!(
            "vfawn: policy chose the native stack; falling back to ipstack (feature not compiled)"
        );
        self.ipstack_backend()
    }

    #[cfg(feature = "backend-ipstack")]
    fn ipstack_backend(&self) -> Box<dyn vfawn_core::StackBackend> {
        let mss = (self.config.device.mtu.min(65535) as u16)
            .saturating_sub(40)
            .max(536);
        Box::new(vfawn_stack_user::IpstackBackend {
            mss,
            udp_nat: std::sync::Arc::new(vfawn_core::UdpNat::from_config(
                &self.config.stack.udp_nat,
                self.config.stack.udp_timeout,
            )),
            dns: std::sync::Arc::new(vfawn_core::DnsHijack::from_config(
                &self.config.dns,
                &self.config.device.inet4_address,
            )),
            udp_timeout_secs: self.config.stack.udp_timeout.as_secs(),
            tcp_timeout_secs: 60,
            broadcast: self.broadcast(),
        })
    }

    /// The device's directed broadcast, from its first IPv4 prefix as
    /// sing-tun's `BroadcastAddr` (stack.go:79) takes it.
    #[cfg(any(feature = "backend-ipstack", feature = "backend-native"))]
    fn broadcast(&self) -> Option<std::net::Ipv4Addr> {
        self.config
            .device
            .inet4_address
            .first()
            .map(ipnet::Ipv4Net::broadcast)
    }

    #[cfg(not(feature = "backend-ipstack"))]
    fn ipstack_backend(&self) -> Box<dyn vfawn_core::StackBackend> {
        eprintln!(
            "vfawn: policy chose the kernel path; falling back to native (feature not compiled)"
        );
        self.native_backend()
    }

    /// The shared tail: capture orchestration, backend spawn, handle.
    fn finish_start(
        &mut self,
        backend: Box<dyn vfawn_core::StackBackend>,
        device: vfawn_device::TunDevice,
        handler: Arc<dyn SessionHandler>,
    ) -> io::Result<()> {
        // Route orchestration installs after the device exists (rules
        // and addresses reference its real name) and before traffic
        // flows (the capture must already own the routing table).
        if self.config.route.auto_route {
            let interface = device.name()?;
            let addresses: Vec<ipnet::IpNet> = self
                .config
                .device
                .inet4_address
                .iter()
                .map(|n| (*n).into())
                .chain(self.config.device.inet6_address.iter().map(|n| (*n).into()))
                .collect();
            self.orchestration = Some(crate::route_orchestration::RouteOrchestration::install(
                &self.config,
                &interface,
                &addresses,
            )?);
            #[cfg(target_os = "linux")]
            {
                self.auto_redirect = crate::route_orchestration::install_auto_redirect(
                    &self.config,
                    &interface,
                    &addresses,
                    Arc::clone(&handler),
                );
            }
        }
        // The Windows firewall rule lets inbound connections reach a
        // stack that accepts them on host sockets; a stack reading the
        // device never does, so it takes none. Other platforms no-op.
        if backend.accepts_on_host_sockets() {
            self.firewall_rule = vfawn_platform::firewall_gate(self.config.route.windows_firewall)?;
        }

        vfawn_core::StackBackend::spawn(backend, Box::new(device), handler).map(|handle| {
            self.handle = Some(handle);
        })
    }

    #[cfg(not(any(feature = "backend-ipstack", feature = "backend-native")))]
    fn start_inner(&mut self, _handler: Arc<dyn SessionHandler>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no stack backend compiled in; enable a backend feature",
        ))
    }

    /// Drain sessions and close the device.
    ///
    /// The order is: stop the stack (which stops accepting new sessions),
    /// give in-flight handlers a bounded window to finish, then drop the
    /// device. Calling shutdown on an already-stopped instance is a no-op.
    /// The route self-heal loop stops before the stack does; the routes
    /// themselves come down after the drain, on every platform.
    pub fn shutdown(&mut self) -> io::Result<()> {
        let Some(handle) = &self.handle else {
            return Ok(());
        };
        // The self-heal loop stops before the stack does: the backend
        // closes the device on its own threads once it sees the stop,
        // and a loop still watching would chase the vanished interface
        // with routes during the drain below.
        if let Some(orchestration) = self.orchestration.as_mut() {
            orchestration.quiesce();
        }
        handle.stop();
        // Give in-flight sessions a bounded window. The transitional
        // backend has no explicit drain API; a bounded wait is the
        // pragmatic answer until the in-house stack lands with one.
        std::thread::sleep(DRAIN_TIMEOUT);
        self.handle = None;
        // The firewall rule follows the same doctrine as the routes
        // below: it must not outlive an orderly shutdown.
        if self.firewall_rule.take().is_some() {
            vfawn_platform::firewall_gate_remove()?;
        }
        // Routing rules outlive a process crash by design; they
        // must not outlive an orderly shutdown. The bypass rules go
        // first: they mark traffic toward routes about to disappear.
        #[cfg(target_os = "linux")]
        drop(self.auto_redirect.take());
        if let Some(mut orchestration) = self.orchestration.take() {
            orchestration
                .remove()
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        Ok(())
    }

    /// Hot-reconfigure the route engine. Builds a new desired state from
    /// the configuration and lets the reconciler drive the kernel toward
    /// it. Returns an error naming the first field that requires a restart
    /// (interface identity, table or rule indices) rather than silently
    /// ignoring it.
    pub fn apply_config(&mut self, config: &VfawnConfig) -> Result<(), ApplyError> {
        let new_desired = vfawn_route::desired_from_config(&vfawn_route::RouteParams {
            interface: &config.device.name.clone().unwrap_or_default(),
            addresses: &config
                .device
                .inet4_address
                .iter()
                .map(|n| n.to_owned().into())
                .collect::<Vec<_>>(),
            captured: &config.route.route_address,
            excluded: &config.route.route_exclude_address,
            table_index: config.route.table_index,
            rule_index: config.route.rule_index,
            mark: config.route.mark,
            bypass_mark: crate::route_orchestration::redirect_marks_of(config).0,
            capture_mark: crate::route_orchestration::redirect_marks_of(config).1,
            strict_route: config.route.strict_route,
            dns_leak_prevention: config.dns.mode == vfawn_core::DnsMode::Hijack,
            include_uid: &config.route.include_uid,
            exclude_uid: &config.route.exclude_uid,
            include_interface: &config.route.include_interface,
            exclude_interface: &config.route.exclude_interface,
        });
        if let Some(reason) = needs_restart_desired(&self.config, config) {
            return Err(ApplyError::NeedsRestart(reason));
        }
        #[cfg(target_os = "linux")]
        if let Some(ref orchestration) = self.orchestration {
            let addresses: Vec<ipnet::IpNet> = self
                .config
                .device
                .inet4_address
                .iter()
                .map(|n| (*n).into())
                .chain(self.config.device.inet6_address.iter().map(|n| (*n).into()))
                .collect();
            return orchestration
                .update(
                    config,
                    &config.device.name.clone().unwrap_or_default(),
                    &addresses,
                )
                .map_err(ApplyError::Reconcile);
        }
        let Some(ref re) = self.reconciler else {
            return Err(ApplyError::NoRouteEngine);
        };
        re.apply(&new_desired).map_err(ApplyError::Reconcile)
    }

    /// Install a route reconciler; the platform layer calls this when it
    /// has a backend ready.
    pub fn set_reconciler(&mut self, reconciler: Reconciler) {
        self.reconciler = Some(reconciler);
    }

    /// Current counters.
    pub fn stats(&self) -> StatsSnapshot {
        let (sessions_total, bytes_forward, bytes_reverse) = self.tracker.snapshot();
        StatsSnapshot {
            sessions_total,
            bytes_forward,
            bytes_reverse,
            panics_contained: self.panics.load(Ordering::Relaxed),
        }
    }

    /// The panic counter shared with data-plane threads; the backend
    /// increments it when a worker thread is caught and contained.
    pub fn panic_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.panics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_is_idempotent() {
        // Construct an instance that never started; shutdown three times.
        let config = VfawnConfig::default();
        let handler = Arc::new(crate::echo::EchoHandler::new());
        let mut instance = Instance::new(config, handler).unwrap();

        instance.shutdown().unwrap();
        instance.shutdown().unwrap();
        instance.shutdown().unwrap();
        assert!(instance.handle.is_none());
    }

    #[test]
    fn double_start_is_rejected() {
        let config = VfawnConfig::default();
        let handler = Arc::new(crate::echo::EchoHandler::new());
        let mut instance = Instance::new(config, handler.clone()).unwrap();

        // On macOS, start will fail (no device backend), but the
        // double-start guard works regardless.
        let _ = instance.start(handler.clone());
        let second = instance.start(handler);
        assert!(second.is_err());
    }

    #[test]
    fn auto_redirect_changes_need_a_restart() {
        let mut base = VfawnConfig::default();
        base.route.auto_route = true;
        let mut on = base.clone();
        on.route.auto_redirect.enabled = true;

        // Toggling either way, or retuning while on.
        assert!(needs_restart_desired(&base, &on).is_some());
        assert!(needs_restart_desired(&on, &base).is_some());
        let mut retuned = on.clone();
        retuned.route.auto_redirect.queue = 101;
        assert!(needs_restart_desired(&on, &retuned).is_some());

        // The escape mark matters only while the bypass is on.
        let mut remarked = on.clone();
        remarked.route.mark = 0x2030;
        assert!(needs_restart_desired(&on, &remarked).is_some());
        let mut remarked_off = base.clone();
        remarked_off.route.mark = 0x2030;
        assert!(needs_restart_desired(&base, &remarked_off).is_none());

        // Exclusions stay hot.
        let mut excluded = on.clone();
        excluded.route.route_exclude_address = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(needs_restart_desired(&on, &excluded).is_none());

        // What the pre-match bakes in is not hot while the bypass is on.
        let mut ranged = on.clone();
        ranged.route.route_address = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(needs_restart_desired(&on, &ranged).is_some());
        let mut filtered = on.clone();
        filtered.route.include_interface = vec!["lo".into()];
        assert!(needs_restart_desired(&on, &filtered).is_some());
        let mut dns = on.clone();
        dns.dns.mode = vfawn_core::DnsMode::Disabled;
        assert!(needs_restart_desired(&on, &dns).is_some());
        let mut ranged_off = base.clone();
        ranged_off.route.route_address = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(needs_restart_desired(&base, &ranged_off).is_none());

        // And the public path refuses before touching any kernel state.
        let handler = Arc::new(crate::echo::EchoHandler::new());
        let mut instance = Instance::new(on, handler).unwrap();
        assert!(matches!(
            instance.apply_config(&base),
            Err(ApplyError::NeedsRestart(_))
        ));
    }

    #[test]
    fn stats_default_is_zeroed() {
        let config = VfawnConfig::default();
        let handler = Arc::new(crate::echo::EchoHandler::new());
        let instance = Instance::new(config, handler).unwrap();
        let stats = instance.stats();
        assert_eq!(stats.sessions_total, 0);
        assert_eq!(stats.panics_contained, 0);
    }
}

/// What went wrong during a hot-reconfiguration attempt.
#[derive(Debug)]
pub enum ApplyError {
    /// A field changed that cannot be hot-updated.
    NeedsRestart(String),
    /// No route engine is installed (non-Linux platform or not started).
    NoRouteEngine,
    /// The reconciler failed; the message describes what happened.
    Reconcile(vfawn_route::ReconcileError),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedsRestart(w) => write!(f, "restart required: {w}"),
            Self::NoRouteEngine => write!(f, "no route engine installed"),
            Self::Reconcile(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ApplyError {}

impl From<ApplyError> for RestartReason {
    fn from(_: ApplyError) -> Self {
        RestartReason::NeedsRestart
    }
}

/// Check whether two configurations differ in non-hot-updatable fields.
fn needs_restart_desired(old: &VfawnConfig, new: &VfawnConfig) -> Option<String> {
    if old.device.mtu != new.device.mtu {
        return Some(format!("mtu {} -> {}", old.device.mtu, new.device.mtu));
    }
    if old.route.table_index != new.route.table_index {
        return Some(format!(
            "table_index {} -> {}",
            old.route.table_index, new.route.table_index
        ));
    }
    if old.route.rule_index != new.route.rule_index {
        return Some(format!(
            "rule_index {} -> {}",
            old.route.rule_index, new.route.rule_index
        ));
    }
    if old.device.name != new.device.name {
        return Some("interface name changed".to_string());
    }
    // The bypass's netfilter table and queue reader are installed once,
    // from the config the instance started with; the route engine alone
    // would follow a hot change, leaving the bypass rule and the marks
    // netfilter writes out of step. Exclusion changes stay hot: a newly
    // excluded prefix judged once more still routes to the main table.
    let (was, now) = (&old.route.auto_redirect, &new.route.auto_redirect);
    if was != now {
        return Some(format!("auto_redirect {was:?} -> {now:?}"));
    }
    // The table spares this process's own sockets by their mark.
    if was.enabled && old.route.mark != new.route.mark {
        return Some(format!(
            "mark {:#x} -> {:#x} under auto_redirect",
            old.route.mark, new.route.mark
        ));
    }
    // The pre-match bakes in the capture range, the interface filters
    // and the DNS mode; the route engine alone would follow a change.
    if was.enabled {
        let (o, n) = (&old.route, &new.route);
        let changed = [
            (o.route_address != n.route_address, "route_address"),
            (
                o.include_interface != n.include_interface,
                "include_interface",
            ),
            (
                o.exclude_interface != n.exclude_interface,
                "exclude_interface",
            ),
            (old.dns.mode != new.dns.mode, "dns mode"),
        ];
        if let Some((_, what)) = changed.iter().find(|(changed, _)| *changed) {
            return Some(format!("{what} changed under auto_redirect"));
        }
    }
    None
}
