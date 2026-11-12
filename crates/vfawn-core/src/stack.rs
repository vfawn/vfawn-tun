// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Stack backend contract.

use crate::device::PacketDevice;
use crate::session::SessionHandler;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// How long aborted sessions get to unwind after a drain gives up on
/// them. An abort only asks; the task still has to be polled once more
/// to drop its state, which on a busy runtime is not instant.
const ABORT_SETTLE: Duration = Duration::from_millis(250);

/// Control over one running termination backend.
///
/// The handle carries the stop signal, the reason when the backend
/// stopped on its own, and, for backends that register their sessions,
/// the set a drain waits on. The ordered part of shutdown (drain
/// sessions, remove routes, close device) is orchestrated above, in the
/// facade, not here.
#[derive(Clone)]
pub struct StackHandle {
    stop: Arc<AtomicBool>,
    failure: Arc<OnceLock<String>>,
    sessions: Arc<SessionSet>,
}

/// What a drain observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Drain {
    /// The backend does not register its sessions; the drain waited the
    /// whole grace window on the backend's word that it owns teardown.
    Untracked,
    /// Every registered session finished inside the grace window.
    Idle,
    /// The grace window ran out with sessions still live; this many were
    /// told to abort.
    Aborted(usize),
}

impl StackHandle {
    /// A handle for a backend that owns its whole teardown (its own
    /// runtime, its own threads): a drain on it can only wait.
    pub fn new() -> Self {
        Self::with_tracking(false)
    }

    /// A handle for a backend that registers every session it starts
    /// through [`StackHandle::enter`], so a drain can end the moment the
    /// last one finishes and abort the stragglers itself. A backend that
    /// runs on a runtime it does not own has to be tracked: nothing else
    /// ends its tasks.
    pub fn tracked() -> Self {
        Self::with_tracking(true)
    }

    fn with_tracking(tracked: bool) -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            failure: Arc::new(OnceLock::new()),
            sessions: Arc::new(SessionSet {
                state: Mutex::new(SessionState {
                    tracked,
                    next: 0,
                    live: HashMap::new(),
                }),
                idle: Condvar::new(),
            }),
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

    /// How many registered sessions are still running.
    pub fn live_sessions(&self) -> usize {
        self.sessions.lock().live.len()
    }

    /// Register one live session. The session counts until the returned
    /// guard drops; `abort` is how a drain that ran out of patience ends
    /// it, and must be safe to call from any thread, at most once.
    pub fn enter(&self, abort: impl Fn() + Send + Sync + 'static) -> SessionGuard {
        let mut state = self.sessions.lock();
        let id = state.next;
        state.next = state.next.wrapping_add(1);
        state.live.insert(id, Arc::new(abort));
        SessionGuard {
            sessions: Arc::clone(&self.sessions),
            id,
        }
    }

    /// Wait for the registered sessions to finish, at most `grace`, then
    /// abort whatever is left. Call after [`StackHandle::stop`]: a backend
    /// still accepting would keep the set from ever emptying.
    ///
    /// Blocks the calling thread. Hosts that run the backend on their own
    /// runtime must not call this from one of that runtime's workers
    /// unless other workers remain free to run the sessions to their end.
    pub fn drain(&self, grace: Duration) -> Drain {
        let deadline = Instant::now() + grace;
        let state = self.sessions.lock();
        if !state.tracked {
            drop(state);
            std::thread::sleep(grace);
            return Drain::Untracked;
        }
        let state = self.sessions.wait_empty(state, deadline);
        if state.live.is_empty() {
            return Drain::Idle;
        }
        let aborts: Vec<Abort> = state.live.values().cloned().collect();
        drop(state);
        // Outside the lock: an abort that drops its task synchronously
        // drops the guard, which takes the same lock.
        for abort in &aborts {
            abort();
        }
        let state = self.sessions.lock();
        drop(
            self.sessions
                .wait_empty(state, Instant::now() + ABORT_SETTLE),
        );
        Drain::Aborted(aborts.len())
    }
}

impl Default for StackHandle {
    fn default() -> Self {
        Self::new()
    }
}

type Abort = Arc<dyn Fn() + Send + Sync>;

/// The sessions a tracked backend has live.
struct SessionSet {
    state: Mutex<SessionState>,
    idle: Condvar,
}

struct SessionState {
    tracked: bool,
    next: u64,
    live: HashMap<u64, Abort>,
}

impl SessionSet {
    /// A poisoned lock only means a session panicked while holding it; the
    /// map itself stays consistent (every write is one insert or remove).
    fn lock(&self) -> MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait_empty<'a>(
        &'a self,
        mut state: MutexGuard<'a, SessionState>,
        deadline: Instant,
    ) -> MutexGuard<'a, SessionState> {
        while !state.live.is_empty() {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            state = self
                .idle
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        state
    }
}

/// One registered session; dropping it is the session's end.
pub struct SessionGuard {
    sessions: Arc<SessionSet>,
    id: u64,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut state = self.sessions.lock();
        state.live.remove(&self.id);
        if state.live.is_empty() {
            self.sessions.idle.notify_all();
        }
    }
}

/// Turns device packets into host-visible sessions.
///
/// One implementation per termination strategy: user-space stack, kernel NAT
/// rewrite, or per-flow mix. The backend owns its threads and its runtime
/// unless it documents a way to borrow the host's; nothing in this
/// contract prescribes them.
pub trait StackBackend: Send {
    /// Start terminating traffic from `device`, handing every session to
    /// `handler`. Returns once the backend is running.
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
    use std::sync::atomic::AtomicUsize;

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

    #[test]
    fn an_untracked_drain_waits_the_whole_window() {
        let handle = StackHandle::new();
        let started = Instant::now();
        assert_eq!(handle.drain(Duration::from_millis(30)), Drain::Untracked);
        assert!(started.elapsed() >= Duration::from_millis(30));
    }

    #[test]
    fn an_idle_tracked_drain_returns_at_once() {
        let handle = StackHandle::tracked();
        let started = Instant::now();
        assert_eq!(handle.drain(Duration::from_secs(5)), Drain::Idle);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_drain_ends_when_the_last_session_does() {
        let handle = StackHandle::tracked();
        let guard = handle.enter(|| {});
        let finisher = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(guard);
        });
        let started = Instant::now();
        assert_eq!(handle.drain(Duration::from_secs(5)), Drain::Idle);
        assert!(started.elapsed() < Duration::from_secs(1));
        finisher.join().unwrap();
    }

    #[test]
    fn stragglers_are_aborted_once_the_window_closes() {
        let handle = StackHandle::tracked();
        let aborted = Arc::new(AtomicUsize::new(0));
        // The abort drops the guard, as a cancelled task drops its own.
        let slot: Arc<Mutex<Option<SessionGuard>>> = Arc::new(Mutex::new(None));
        let guard = {
            let aborted = Arc::clone(&aborted);
            let slot = Arc::clone(&slot);
            handle.enter(move || {
                aborted.fetch_add(1, Ordering::SeqCst);
                slot.lock().unwrap().take();
            })
        };
        *slot.lock().unwrap() = Some(guard);
        let _left_running = handle.enter(|| {});
        assert_eq!(handle.drain(Duration::from_millis(20)), Drain::Aborted(2));
        assert_eq!(aborted.load(Ordering::SeqCst), 1);
    }
}
