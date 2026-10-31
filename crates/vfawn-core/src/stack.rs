// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Stack backend contract.

use crate::device::PacketDevice;
use crate::session::SessionHandler;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Control over one running termination backend.
///
/// The handle carries a stop signal and nothing else: backends poll the flag
/// in their event loops and own their drain and teardown. The ordered part
/// of shutdown (drain sessions, remove routes, close device) is orchestrated
/// above, in the facade, not here.
#[derive(Clone)]
pub struct StackHandle {
    stop: Arc<AtomicBool>,
}

impl StackHandle {
    /// Create a handle whose stop flag is clear. The backend it belongs to
    /// keeps a clone and polls [`StackHandle::is_stopped`] each loop
    /// iteration.
    pub fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request shutdown. Idempotent.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// Whether shutdown has been requested.
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
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
}
