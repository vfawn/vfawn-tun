// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The auto-reconciliation loop: when the network changes, drive the
//! kernel back toward the desired state without human intervention.
//!
//! A dedicated thread receives events from the monitor (019), debounces
//! them, and calls the reconciler (017). The single-flight pattern
//! prevents storms: events arriving during an in-progress reconciliation
//! coalesce into at most one follow-up pass.

use crate::model::DesiredState;
use crate::reconciler::Reconciler;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::Duration;
use vfawn_core::MonitorEvent;

/// How long to wait after the first event before reconciling, so rapid
/// bursts coalesce into one pass.
const DEBOUNCE: Duration = Duration::from_millis(200);

/// The auto-reconciliation loop.
pub struct AutoReconciler {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    reconcile_count: Arc<AtomicU64>,
}

impl AutoReconciler {
    /// Start auto-reconciling toward `desired` whenever `events` produces
    /// a MonitorEvent.
    ///
    /// The thread drains the event channel continuously but only calls
    /// the reconciler after a debounce window; events during an active
    /// reconciliation set a pending flag that triggers one more pass.
    pub fn start(
        desired: Arc<std::sync::RwLock<DesiredState>>,
        reconciler: Arc<Reconciler>,
        events: Receiver<MonitorEvent>,
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let reconcile_count = Arc::new(AtomicU64::new(0));
        let flag = Arc::clone(&shutdown);
        let counter = Arc::clone(&reconcile_count);

        let handle = std::thread::Builder::new()
            .name("vfawn-auto-reconcile".into())
            .spawn(move || {
                let mut pending = false;
                loop {
                    if flag.load(Ordering::Acquire) {
                        break;
                    }

                    // Drain events with a debounce: wait for the first
                    // event, then coalesce anything that arrives during
                    // the window.
                    let got_event = drain_events(&events, &flag, DEBOUNCE);
                    if got_event || pending {
                        // Re-read the desired state (it may have been
                        // hot-updated since the last pass).
                        let snapshot = desired.read().expect("desired state lock poisoned").clone();
                        match reconciler.apply(&snapshot) {
                            Ok(()) => {}
                            Err(e) => {
                                eprintln!("auto-reconcile: {e}");
                            }
                        }
                        counter.fetch_add(1, Ordering::Relaxed);
                        // Check if more events arrived while we were busy.
                        pending = drain_events(&events, &flag, Duration::ZERO);
                    }
                }
            })
            .expect("spawn auto-reconcile thread");

        Self {
            shutdown,
            handle: Some(handle),
            reconcile_count,
        }
    }

    /// How many reconciliation passes have run.
    pub fn reconcile_count(&self) -> u64 {
        self.reconcile_count.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

impl Drop for AutoReconciler {
    fn drop(&mut self) {
        self.stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Drain pending events for up to `window`. Returns true if any event
/// was received.
fn drain_events(events: &Receiver<MonitorEvent>, shutdown: &AtomicBool, window: Duration) -> bool {
    let deadline = std::time::Instant::now() + window;
    let mut got_any = false;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return got_any;
        }
        let timeout = deadline.saturating_duration_since(std::time::Instant::now());
        if timeout.is_zero() && got_any {
            return got_any;
        }
        match events.recv_timeout(if got_any { Duration::ZERO } else { timeout }) {
            Ok(_event) => got_any = true,
            Err(_) => return got_any,
        }
    }
}
