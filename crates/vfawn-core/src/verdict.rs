// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Verdict execution: turn a `judge_flow` decision into the right
//! physical action for each verdict variant.
//!
//! The executor is a pure policy component: given the verdict and the
//! flow context, it tells the caller what to do (create a session, drop
//! the stream, or note an unsupported action for the transitional
//! backend). The actual wire-level work (RST injection, destination
//! rewrite) belongs to the stack; the executor only decides.

use crate::{FlowInfo, FlowTrackerHook, Verdict};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// What the caller should physically do after a verdict.
#[derive(Clone)]
pub enum VerdictAction {
    /// Create a session and hand it to the handler.
    CreateSession {
        udp_timeout_override: Option<Duration>,
        tracker: Option<Arc<CountingTracker>>,
    },
    /// Drop the stream without any wire response.
    Drop,
    /// Reset the connection (RST for TCP, unreachable for datagram).
    /// In the transitional backend this is equivalent to Drop; the
    /// in-house stack sends the actual RST.
    Reset,
    /// Redirect to a different destination. The transitional backend
    /// cannot rewrite destinations inside ipstack; the in-house stack
    /// will handle this.
    RedirectTo(String),
}

/// A byte-counting tracker wrapper that reports through the host hook.
///
/// Wraps the raw `FlowTrackerHook` with atomic counters so the verdict
/// executor can verify counts match in tests.
pub struct CountingTracker {
    pub forward: AtomicU64,
    pub reverse: AtomicU64,
    pub established: AtomicU64,
    pub closed: AtomicU64,
    closed_reported: AtomicBool,
    hook: Option<Arc<dyn FlowTrackerHook>>,
}

impl CountingTracker {
    pub fn new(hook: Option<Arc<dyn FlowTrackerHook>>) -> Self {
        Self {
            forward: AtomicU64::new(0),
            reverse: AtomicU64::new(0),
            established: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            closed_reported: AtomicBool::new(false),
            hook,
        }
    }

    pub fn add_forward(&self, n: u64) {
        self.forward.fetch_add(n, Ordering::Relaxed);
        if let Some(ref h) = self.hook {
            h.count_forward(n);
        }
    }

    pub fn add_reverse(&self, n: u64) {
        self.reverse.fetch_add(n, Ordering::Relaxed);
        if let Some(ref h) = self.hook {
            h.count_reverse(n);
        }
    }

    pub fn mark_established(&self) {
        self.established.fetch_add(1, Ordering::Relaxed);
        if let Some(ref h) = self.hook {
            h.established();
        }
    }

    /// Report the close exactly once: two owners of a flow (the NAT
    /// table timing it out, the session handle being dropped) may both
    /// try, and the first reason to arrive is the truest one.
    pub fn mark_closed(&self, reason: crate::CloseReason) {
        if self.closed_reported.swap(true, Ordering::AcqRel) {
            return;
        }
        self.closed.fetch_add(1, Ordering::Relaxed);
        if let Some(ref h) = self.hook {
            h.closed(reason);
        }
    }
}

impl FlowTrackerHook for CountingTracker {
    fn count_forward(&self, n: u64) {
        CountingTracker::add_forward(self, n);
    }
    fn count_reverse(&self, n: u64) {
        CountingTracker::add_reverse(self, n);
    }
    fn established(&self) {
        CountingTracker::mark_established(self);
    }
    fn closed(&self, reason: crate::CloseReason) {
        CountingTracker::mark_closed(self, reason);
    }
}

/// Decide what to do for a given verdict.
///
/// The mapping follows the contract (06 §二):
/// * Accept → create session;
/// * AcceptWith → create session with per-flow overrides;
/// * Bypass → same as Accept at the session layer (no "put it back"
///   channel exists in a user-space stack);
/// * Drop → silently discard;
/// * Reject → reset (RST for TCP);
/// * Redirect → redirect to the new destination (in-house stack only
///   for now).
pub fn execute(verdict: Verdict, _flow: &FlowInfo) -> VerdictAction {
    match verdict {
        Verdict::Accept => VerdictAction::CreateSession {
            udp_timeout_override: None,
            tracker: None,
        },
        Verdict::AcceptWith {
            udp_timeout,
            tracker,
        } => VerdictAction::CreateSession {
            udp_timeout_override: udp_timeout,
            tracker: tracker.map(|t| Arc::new(CountingTracker::new(Some(t)))),
        },
        Verdict::Bypass => VerdictAction::CreateSession {
            udp_timeout_override: None,
            tracker: None,
        },
        Verdict::Drop => VerdictAction::Drop,
        Verdict::Reject => VerdictAction::Reset,
        Verdict::Redirect(addr) => VerdictAction::RedirectTo(addr.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CloseReason, FlowInfo, Network};
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicU64;

    fn test_flow() -> FlowInfo {
        FlowInfo {
            network: Network::Tcp,
            source: "192.168.1.1:12345".parse::<SocketAddr>().unwrap(),
            destination: "10.0.0.1:443".parse::<SocketAddr>().unwrap(),
        }
    }

    #[test]
    fn accept_creates_session() {
        let action = execute(Verdict::Accept, &test_flow());
        assert!(matches!(action, VerdictAction::CreateSession { .. }));
    }

    #[test]
    fn accept_with_carries_overrides() {
        let action = execute(
            Verdict::AcceptWith {
                udp_timeout: Some(Duration::from_secs(60)),
                tracker: None,
            },
            &test_flow(),
        );
        match action {
            VerdictAction::CreateSession {
                udp_timeout_override,
                ..
            } => assert_eq!(udp_timeout_override, Some(Duration::from_secs(60))),
            _ => panic!("expected CreateSession"),
        }
    }

    #[test]
    fn bypass_is_accept_at_session_layer() {
        let action = execute(Verdict::Bypass, &test_flow());
        assert!(matches!(action, VerdictAction::CreateSession { .. }));
    }

    #[test]
    fn drop_silently_discards() {
        let action = execute(Verdict::Drop, &test_flow());
        assert!(matches!(action, VerdictAction::Drop));
    }

    #[test]
    fn reject_resets() {
        let action = execute(Verdict::Reject, &test_flow());
        assert!(matches!(action, VerdictAction::Reset));
    }

    #[test]
    fn redirect_targets_new_destination() {
        let action = execute(
            Verdict::Redirect("10.99.0.1:8443".parse::<SocketAddr>().unwrap()),
            &test_flow(),
        );
        assert!(matches!(&action, VerdictAction::RedirectTo(a) if a == "10.99.0.1:8443"));
    }

    #[test]
    fn counting_tracker_counts_both_directions() {
        let tracker = Arc::new(CountingTracker::new(None));
        tracker.add_forward(100);
        tracker.add_forward(50);
        tracker.add_reverse(200);
        tracker.mark_established();
        tracker.mark_closed(CloseReason::Finished);

        assert_eq!(tracker.forward.load(Ordering::Relaxed), 150);
        assert_eq!(tracker.reverse.load(Ordering::Relaxed), 200);
        assert_eq!(tracker.established.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.closed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn only_the_first_close_reaches_the_hook() {
        struct ReasonSink {
            reported: std::sync::Mutex<Vec<crate::CloseReason>>,
        }
        impl FlowTrackerHook for ReasonSink {
            fn count_forward(&self, _n: u64) {}
            fn count_reverse(&self, _n: u64) {}
            fn established(&self) {}
            fn closed(&self, reason: crate::CloseReason) {
                self.reported.lock().unwrap().push(reason);
            }
        }
        let sink = Arc::new(ReasonSink {
            reported: std::sync::Mutex::new(Vec::new()),
        });
        let tracker = CountingTracker::new(Some(sink.clone()));
        tracker.mark_closed(crate::CloseReason::Timeout);
        tracker.mark_closed(crate::CloseReason::Finished);
        assert_eq!(
            *sink.reported.lock().unwrap(),
            vec![crate::CloseReason::Timeout]
        );
    }

    #[test]
    fn counting_tracker_passes_through_to_host_hook() {
        struct RecordingHook {
            forward: AtomicU64,
            reverse: AtomicU64,
        }
        impl FlowTrackerHook for RecordingHook {
            fn count_forward(&self, n: u64) {
                self.forward.fetch_add(n, Ordering::Relaxed);
            }
            fn count_reverse(&self, n: u64) {
                self.reverse.fetch_add(n, Ordering::Relaxed);
            }
            fn established(&self) {}
            fn closed(&self, _: crate::CloseReason) {}
        }
        let hook = Arc::new(RecordingHook {
            forward: AtomicU64::new(0),
            reverse: AtomicU64::new(0),
        });
        let tracker = CountingTracker::new(Some(hook.clone()));
        tracker.add_forward(42);
        tracker.add_reverse(17);
        assert_eq!(hook.forward.load(Ordering::Relaxed), 42);
        assert_eq!(hook.reverse.load(Ordering::Relaxed), 17);
    }
}
