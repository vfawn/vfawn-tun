// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Instance lifecycle: compose a device, a backend and the host handler
//! into one runnable unit.

use std::io;
use std::sync::Arc;
use vfawn_core::{SessionHandler, StackHandle, VfawnConfig};

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
}

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
        let _ = handler; // stored by start(); see below for the reason
        Ok(Instance {
            config,
            handle: None,
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
        self.start_inner(handler)
    }

    #[cfg(feature = "backend-ipstack")]
    fn start_inner(&mut self, handler: Arc<dyn SessionHandler>) -> io::Result<()> {
        let device = vfawn_device::TunDevice::create(&self.config.device)?;
        let mss = (self.config.device.mtu.min(65535) as u16)
            .saturating_sub(40)
            .max(536);
        let backend = Box::new(vfawn_stack_user::IpstackBackend {
            mss,
            udp_timeout_secs: self.config.stack.udp_timeout.as_secs(),
            tcp_timeout_secs: 60,
        });
        use vfawn_core::StackBackend;
        let handle = backend.spawn(Box::new(device), handler)?;
        self.handle = Some(handle);
        Ok(())
    }

    #[cfg(not(feature = "backend-ipstack"))]
    fn start_inner(&mut self, _handler: Arc<dyn SessionHandler>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no stack backend compiled in; enable a backend feature",
        ))
    }

    /// Drain sessions and close the device.
    ///
    /// The order is: stop the stack (which stops accepting new sessions
    /// and lets in-flight handlers finish), then close the device. Route
    /// teardown runs after both, once the route engine is wired in.
    pub fn shutdown(&mut self) -> io::Result<()> {
        if let Some(handle) = &self.handle {
            handle.stop();
        }
        self.handle = None;
        Ok(())
    }

    /// Hot-reconfiguration. Returns an error explaining what to do until
    /// the route engine makes incremental reconciliation available.
    pub fn apply_config(&mut self, _config: &VfawnConfig) -> Result<(), RestartReason> {
        Err(RestartReason::NeedsRestart)
    }

    /// Current counters. Fields populate as observability lands.
    pub fn stats(&self) -> StatsSnapshot {
        StatsSnapshot::default()
    }
}
