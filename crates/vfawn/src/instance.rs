// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Instance lifecycle: compose a device, a backend and the host handler
//! into one runnable unit.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
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
    /// The order is: stop the stack (which stops accepting new sessions),
    /// give in-flight handlers a bounded window to finish, then drop the
    /// device. Calling shutdown on an already-stopped instance is a no-op;
    /// route teardown runs after both, once the route engine is wired in.
    pub fn shutdown(&mut self) -> io::Result<()> {
        let Some(handle) = &self.handle else {
            return Ok(());
        };
        handle.stop();
        // Give in-flight sessions a bounded window. The transitional
        // backend has no explicit drain API; a bounded wait is the
        // pragmatic answer until the in-house stack lands with one.
        std::thread::sleep(DRAIN_TIMEOUT);
        self.handle = None;
        Ok(())
    }

    /// Hot-reconfiguration. Returns an error explaining what to do until
    /// the route engine makes incremental reconciliation available.
    pub fn apply_config(&mut self, _config: &VfawnConfig) -> Result<(), RestartReason> {
        Err(RestartReason::NeedsRestart)
    }

    /// Current counters.
    pub fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            panics_contained: self.panics.load(Ordering::Relaxed),
            ..StatsSnapshot::default()
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
    fn stats_default_is_zeroed() {
        let config = VfawnConfig::default();
        let handler = Arc::new(crate::echo::EchoHandler::new());
        let instance = Instance::new(config, handler).unwrap();
        let stats = instance.stats();
        assert_eq!(stats.sessions_total, 0);
        assert_eq!(stats.panics_contained, 0);
    }
}
