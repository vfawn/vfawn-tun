// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! NAT-mode behavior: symmetric mode must keep destinations apart,
//! endpoint-independent mode must share one session across them, idle
//! state must expire into a tracker report, and capacity must evict the
//! stalest item rather than refuse service.
//!
//! Time is a parameter, so every expiry here is arithmetic, not sleep.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vfawn_core::{CloseReason, FlowTrackerHook, UdpNat, UdpSessionMode, config::UdpNatConfig};

const fn addr(last: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, last), port))
}

const HOST: SocketAddr = addr(10, 50000);
const DNS_A: SocketAddr = addr(20, 53);
const DNS_B: SocketAddr = addr(21, 53);

/// Records the close reason the table reports, so timeout assertions
/// can check the reason itself, not just that something fired.
#[derive(Default)]
struct ReasonLog {
    forward: AtomicU64,
    closes: Mutex<Vec<CloseReason>>,
}

impl FlowTrackerHook for ReasonLog {
    fn count_forward(&self, n: u64) {
        self.forward.fetch_add(n, Ordering::Relaxed);
    }
    fn count_reverse(&self, _n: u64) {}
    fn established(&self) {}
    fn closed(&self, reason: CloseReason) {
        self.closes.lock().unwrap().push(reason);
    }
}

fn symmetric() -> UdpNat {
    UdpNat::with_shards(UdpSessionMode::Symmetric, Duration::from_secs(300), 0, 4)
}

fn endpoint_independent() -> UdpNat {
    UdpNat::with_shards(
        UdpSessionMode::EndpointIndependent,
        Duration::from_secs(300),
        0,
        4,
    )
}

#[test]
fn symmetric_mode_splits_destinations_into_two_sessions() {
    let nat = symmetric();

    let to_a = nat.on_outbound(HOST, DNS_A, None, None, Instant::now());
    let to_b = nat.on_outbound(HOST, DNS_B, None, None, Instant::now());

    assert!(to_a.created && to_b.created);
    assert_ne!(
        to_a.session_id, to_b.session_id,
        "destinations are separate sessions"
    );
    assert_eq!(nat.session_count(), 2);

    // Return traffic from both destinations routes back.
    let now = Instant::now();
    assert!(nat.on_inbound(HOST, DNS_A, now).is_some());
    assert!(nat.on_inbound(HOST, DNS_B, now).is_some());
    // A remote that never saw an outbound datagram gets nothing.
    assert_eq!(nat.on_inbound(HOST, addr(30, 53), now), None);
}

#[test]
fn ei_mode_shares_one_session_across_destinations() {
    let nat = endpoint_independent();

    let first = nat.on_outbound(HOST, DNS_A, None, None, Instant::now());
    let second = nat.on_outbound(HOST, DNS_B, None, None, Instant::now());
    let again = nat.on_outbound(HOST, DNS_A, None, None, Instant::now());

    assert!(first.created);
    assert!(!second.created && second.remote_added);
    assert_eq!(
        first.session_id, second.session_id,
        "one session, two remotes"
    );
    assert_eq!(again.session_id, first.session_id);
    assert!(!again.remote_added, "known remote is a refresh, not an add");
    assert_eq!(nat.session_count(), 1);

    let now = Instant::now();
    assert_eq!(nat.on_inbound(HOST, DNS_A, now), Some(first.session_id));
    assert_eq!(nat.on_inbound(HOST, DNS_B, now), Some(first.session_id));
    assert_eq!(nat.on_inbound(HOST, addr(30, 53), now), None);
}

#[test]
fn idle_sessions_expire_with_timeout_reported() {
    let nat = symmetric();
    let hook = Arc::new(ReasonLog::default());
    let t0 = Instant::now();

    nat.on_outbound(HOST, DNS_A, Some(hook.clone()), None, t0);
    assert_eq!(hook.closes.lock().unwrap().len(), 0);

    // One second short: still resident.
    assert_eq!(nat.sweep(t0 + Duration::from_secs(299)), 0);
    assert_eq!(nat.session_count(), 1);

    // Past the deadline: reaped, and the tracker heard Timeout.
    assert_eq!(nat.sweep(t0 + Duration::from_secs(301)), 1);
    assert_eq!(nat.session_count(), 0);
    assert_eq!(*hook.closes.lock().unwrap(), vec![CloseReason::Timeout]);
}

#[test]
fn ei_remote_path_expires_before_the_session() {
    let nat = endpoint_independent();
    let timeout = Duration::from_secs(300);
    let t0 = Instant::now();

    nat.on_outbound(HOST, DNS_A, None, None, t0);
    nat.on_outbound(HOST, DNS_B, None, None, t0);

    // Half the session timeout is a remote path's lifetime. Neither
    // remote has heard anything since t0; both paths die at t0+150s
    // while the session itself lives to t0+300s.
    let t_mid = t0 + timeout / 2 + Duration::from_secs(1);
    assert_eq!(nat.sweep(t_mid), 0);
    assert_eq!(nat.session_count(), 1, "session outlives its remote paths");
    assert_eq!(
        nat.on_inbound(HOST, DNS_A, t_mid),
        None,
        "stale path is gone"
    );

    // Fresh traffic re-opens the path on the same session.
    let outcome = nat.on_outbound(HOST, DNS_A, None, None, t_mid);
    assert!(!outcome.created && outcome.remote_added);
    assert_eq!(
        outcome.session_id,
        nat.on_inbound(HOST, DNS_A, t_mid).unwrap()
    );
}

#[test]
fn capacity_evicts_the_stalest_and_admits_the_new_flow() {
    // Sessions and remote paths both count as entries; two symmetric
    // sessions occupy the full budget of four.
    let nat = UdpNat::with_shards(UdpSessionMode::Symmetric, Duration::from_secs(300), 4, 2);
    let stale_hook = Arc::new(ReasonLog::default());
    let t0 = Instant::now();

    nat.on_outbound(addr(1, 5000), DNS_A, Some(stale_hook.clone()), None, t0);

    // The second session keeps receiving traffic, so the first one is
    // the stalest when capacity runs out.
    let live = addr(2, 5001);
    nat.on_outbound(live, DNS_A, None, None, t0);
    let t1 = t0 + Duration::from_secs(100);
    nat.on_outbound(live, DNS_A, None, None, t1);

    // A third flow must be admitted, evicting the stale one.
    let third = nat.on_outbound(addr(3, 5002), DNS_A, None, None, t1);
    assert!(third.created, "capacity never refuses a new flow");
    assert!(nat.evicted_by_capacity() >= 1);
    assert_eq!(
        *stale_hook.closes.lock().unwrap(),
        vec![CloseReason::Timeout],
        "the evicted session reported its close"
    );
    // The live session survived the eviction.
    assert_eq!(nat.on_inbound(live, DNS_A, t1).unwrap(), 2);
}

#[test]
fn config_constructs_the_table_the_host_configured() {
    let config = UdpNatConfig {
        mode: UdpSessionMode::EndpointIndependent,
        max_entries: 8,
    };
    let nat = UdpNat::from_config(&config, Duration::from_secs(60));

    let first = nat.on_outbound(
        HOST,
        DNS_A,
        None,
        Some(Duration::from_secs(5)),
        Instant::now(),
    );
    let second = nat.on_outbound(HOST, DNS_B, None, None, Instant::now());
    assert_eq!(first.session_id, second.session_id, "EI mode from config");
}

#[test]
fn timeout_override_shortens_the_session() {
    let nat = symmetric();
    let hook = Arc::new(ReasonLog::default());
    let t0 = Instant::now();

    nat.on_outbound(
        HOST,
        DNS_A,
        Some(hook.clone()),
        Some(Duration::from_secs(10)),
        t0,
    );
    assert_eq!(nat.sweep(t0 + Duration::from_secs(11)), 1);
    assert_eq!(*hook.closes.lock().unwrap(), vec![CloseReason::Timeout]);
}
