// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Instance-level accounting: one tracker shared by every session the
//! instance runs, no matter which engine terminates it or what the
//! host's own handler wanted to count. The wrapper handler below
//! attaches this tracker to each accepted flow through the verdict
//! contract — the same pipe a host's own tracker rides — so the
//! counters are exactly what the sessions reported, nothing inferred.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use vfawn_core::{
    Action, CloseReason, FlowInfo, FlowTrackerHook, IcmpPacket, SessionHandler, TcpSession,
    UdpSession, Verdict,
};

/// The instance's own counters, one shared set for every session.
#[derive(Default)]
pub struct InstanceTracker {
    established: AtomicU64,
    forward: AtomicU64,
    reverse: AtomicU64,
}

impl InstanceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// The three numbers [`crate::instance::StatsSnapshot`] reports.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.established.load(Ordering::Relaxed),
            self.forward.load(Ordering::Relaxed),
            self.reverse.load(Ordering::Relaxed),
        )
    }
}

impl FlowTrackerHook for InstanceTracker {
    fn count_forward(&self, n: u64) {
        self.forward.fetch_add(n, Ordering::Relaxed);
    }

    fn count_reverse(&self, n: u64) {
        self.reverse.fetch_add(n, Ordering::Relaxed);
    }

    fn established(&self) {
        self.established.fetch_add(1, Ordering::Relaxed);
    }

    fn closed(&self, _reason: CloseReason) {}
}

/// Two hooks called in order: the host's own first (its expectations
/// about call order predate this wrapper), the instance's second.
struct FanoutTracker {
    host: Option<Arc<dyn FlowTrackerHook>>,
    instance: Arc<InstanceTracker>,
}

impl FlowTrackerHook for FanoutTracker {
    fn count_forward(&self, n: u64) {
        if let Some(host) = &self.host {
            host.count_forward(n);
        }
        self.instance.count_forward(n);
    }

    fn count_reverse(&self, n: u64) {
        if let Some(host) = &self.host {
            host.count_reverse(n);
        }
        self.instance.count_reverse(n);
    }

    fn established(&self) {
        if let Some(host) = &self.host {
            host.established();
        }
        self.instance.established();
    }

    fn closed(&self, reason: CloseReason) {
        if let Some(host) = &self.host {
            host.closed(reason);
        }
        self.instance.closed(reason);
    }
}

/// The handler the instance actually runs: the host's handler with
/// the instance's tracker attached to every accepted flow. A verdict
/// that already carries a tracker keeps it — both hooks hear the same
/// session, the host's first.
pub struct StatsHandler {
    host: Arc<dyn SessionHandler>,
    instance: Arc<InstanceTracker>,
}

impl StatsHandler {
    pub fn new(host: Arc<dyn SessionHandler>, instance: Arc<InstanceTracker>) -> Self {
        Self { host, instance }
    }

    /// Attach the instance's counting to the host's verdict.
    fn tracked(&self, verdict: Verdict) -> Verdict {
        match verdict {
            Verdict::Accept => Verdict::AcceptWith {
                udp_timeout: None,
                tracker: Some(Arc::new(FanoutTracker {
                    host: None,
                    instance: Arc::clone(&self.instance),
                })),
            },
            Verdict::AcceptWith {
                udp_timeout,
                tracker,
            } => Verdict::AcceptWith {
                udp_timeout,
                tracker: Some(Arc::new(FanoutTracker {
                    host: tracker,
                    instance: Arc::clone(&self.instance),
                })),
            },
            other => other,
        }
    }
}

#[async_trait::async_trait]
impl SessionHandler for StatsHandler {
    fn judge_flow(&self, flow: &FlowInfo, first_packet: &[u8]) -> Verdict {
        self.tracked(self.host.judge_flow(flow, first_packet))
    }

    async fn on_tcp(&self, session: TcpSession) {
        self.host.on_tcp(session).await;
    }

    async fn on_udp(&self, session: UdpSession) {
        self.host.on_udp(session).await;
    }

    async fn on_icmp(&self, packet: IcmpPacket) -> Action {
        self.host.on_icmp(packet).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    struct HostTracker {
        forward: AtomicU64,
        established: AtomicU64,
    }

    impl FlowTrackerHook for HostTracker {
        fn count_forward(&self, n: u64) {
            self.forward.fetch_add(n, Ordering::Relaxed);
        }
        fn count_reverse(&self, _n: u64) {}
        fn established(&self) {
            self.established.fetch_add(1, Ordering::Relaxed);
        }
        fn closed(&self, _reason: CloseReason) {}
    }

    struct Counting;

    #[async_trait::async_trait]
    impl SessionHandler for Counting {
        fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
            Verdict::Accept
        }
        async fn on_tcp(&self, _session: TcpSession) {}
        async fn on_udp(&self, _session: UdpSession) {}
        async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
            Action::Drop
        }
    }

    #[test]
    fn an_accepted_flow_carries_the_instance_tracker() {
        let tracker = Arc::new(InstanceTracker::new());
        let handler = StatsHandler::new(Arc::new(Counting), Arc::clone(&tracker));
        let verdict = handler.judge_flow(&sample_flow(), &[]);
        let Verdict::AcceptWith {
            tracker: Some(hook),
            ..
        } = verdict
        else {
            panic!("the wrapper attaches a tracker to every accept");
        };
        hook.established();
        hook.count_forward(10);
        hook.count_reverse(4);
        assert_eq!(tracker.snapshot(), (1, 10, 4));
    }

    #[test]
    fn a_host_tracker_keeps_hearing_alongside_the_instance() {
        let host_tracker = Arc::new(HostTracker {
            forward: AtomicU64::new(0),
            established: AtomicU64::new(0),
        });
        struct WithTracker(Arc<HostTracker>);
        #[async_trait::async_trait]
        impl SessionHandler for WithTracker {
            fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
                Verdict::AcceptWith {
                    udp_timeout: None,
                    tracker: Some(Arc::clone(&self.0) as Arc<dyn FlowTrackerHook>),
                }
            }
            async fn on_tcp(&self, _session: TcpSession) {}
            async fn on_udp(&self, _session: UdpSession) {}
            async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
                Action::Drop
            }
        }

        let instance = Arc::new(InstanceTracker::new());
        let handler = StatsHandler::new(
            Arc::new(WithTracker(Arc::clone(&host_tracker))),
            Arc::clone(&instance),
        );
        let verdict = handler.judge_flow(&sample_flow(), &[]);
        let Verdict::AcceptWith {
            tracker: Some(hook),
            ..
        } = verdict
        else {
            panic!("the wrapper preserves the accept-with shape");
        };
        hook.established();
        hook.count_forward(7);
        assert_eq!(instance.snapshot(), (1, 7, 0));
        assert_eq!(
            host_tracker.established.load(Ordering::Relaxed),
            1,
            "the host's own tracker still hears every call"
        );
        assert_eq!(host_tracker.forward.load(Ordering::Relaxed), 7);
    }

    fn sample_flow() -> FlowInfo {
        FlowInfo {
            network: vfawn_core::Network::Tcp,
            source: "198.18.0.2:40000".parse().unwrap(),
            destination: "203.0.113.1:443".parse().unwrap(),
        }
    }
}
