// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Stack backend contract.

use crate::device::PacketDevice;
use crate::session::SessionHandler;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// Control over one running termination backend.
///
/// The handle carries a stop signal and, when the backend stopped on its
/// own, the reason: backends poll the flag in their event loops and own
/// their drain and teardown. The ordered part of shutdown (drain
/// sessions, remove routes, close device) is orchestrated above, in the
/// facade, not here.
#[derive(Clone)]
pub struct StackHandle {
    stop: Arc<AtomicBool>,
    failure: Arc<OnceLock<String>>,
}

impl StackHandle {
    /// Create a handle whose stop flag is clear. The backend it belongs to
    /// keeps a clone and polls [`StackHandle::is_stopped`] each loop
    /// iteration.
    pub fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            failure: Arc::new(OnceLock::new()),
        }
    }

    /// The backend stopped on its own: the device went away under it.
    /// As sing-tun's engine does on a read error it cannot recover from
    /// (`stack_go_engine.go:283-286`), the backend stops rather than
    /// retries or rebuilds; restarting is the host's call, and this
    /// records why. A stop the host already asked for is not a
    /// failure, so it is then left alone. Returns whether this call
    /// recorded the failure.
    pub fn fail(&self, reason: impl Into<String>) -> bool {
        if self.stop.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.failure.set(reason.into()).is_ok()
    }

    /// Why the backend stopped on its own; `None` while it runs and
    /// after a stop the host asked for.
    pub fn failure(&self) -> Option<String> {
        self.failure.get().cloned()
    }

    /// Request shutdown. Idempotent.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// Whether shutdown has been requested.
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// The stop flag itself, for backends that park a watcher on it
    /// instead of polling between work.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }
}

impl Default for StackHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Turns device packets into host-visible sessions.
///
/// One implementation per termination strategy: user-space stack, kernel NAT
/// rewrite, or per-flow mix. The backend owns its threads and its runtime;
/// nothing in this contract prescribes them.
pub trait StackBackend: Send {
    /// Start terminating traffic from `device`, handing every session to
    /// `handler`. Returns once the backend is running on its own threads.
    fn spawn(
        self: Box<Self>,
        device: Box<dyn PacketDevice>,
        handler: Arc<dyn SessionHandler>,
    ) -> io::Result<StackHandle>;

    /// Whether this backend terminates flows on host sockets, as the
    /// system stack's listeners do, and so needs the host firewall to
    /// let inbound connections reach the process. sing-tun takes its
    /// Windows inbound rule for that stack alone (`stack_system.go:145`);
    /// a stack that reads the device itself never accepts on a socket.
    fn accepts_on_host_sockets(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_stops_the_backend_and_keeps_its_reason() {
        let handle = StackHandle::new();
        assert_eq!(handle.failure(), None);
        assert!(handle.fail("device is down"));
        assert!(handle.is_stopped());
        assert_eq!(handle.failure().as_deref(), Some("device is down"));
        // The first reason stands.
        assert!(!handle.fail("later"));
        assert_eq!(handle.failure().as_deref(), Some("device is down"));
    }

    #[test]
    fn a_stop_the_host_asked_for_is_not_a_failure() {
        let handle = StackHandle::new();
        handle.stop();
        // The device going away during an orderly stop is expected.
        assert!(!handle.fail("device is down"));
        assert_eq!(handle.failure(), None);
    }
}
