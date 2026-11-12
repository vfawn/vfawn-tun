// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The darwin acceptance shape: an instance takes over a prefix
//! through the platform's own route command, answers for its stats,
//! and an orderly shutdown leaves the route table as it found it.
//! Run elevated (the CI runner is administrator):
//!
//! ```text
//! sudo -E cargo test -p vfawn --test macos_e2e -- --ignored --exact --nocapture
//! ```

#![cfg(target_os = "macos")]

use std::collections::BTreeSet;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vfawn::echo::EchoHandler;
use vfawn::instance::Instance;
use vfawn_core::VfawnConfig;

/// The prefix the capture owns, and an address inside it to ask the
/// route table about.
const CAPTURED: &str = "198.18.0.0/15";
const ASK_ABOUT: &str = "198.18.0.50";
/// An address outside the captured prefix: it must keep answering
/// through whatever the host routed it through before.
const OUTSIDE: &str = "1.1.1.1";

#[test]
#[ignore]
fn takeover_stats_and_clean_teardown() {
    // Root: the route table edits need it.
    assert_root();

    let outside_before = route_names(OUTSIDE);
    // The kernel picks the unit: a fixed name collides with whatever
    // utun the host already runs (EBUSY on a machine where a VPN holds
    // utun9). The adapter is the one interface start added.
    let interfaces_before = interfaces();
    let handler = Arc::new(EchoHandler::new());
    let mut config = VfawnConfig::default();
    config.device.mtu = 1500;
    config.device.inet4_address = vec!["198.18.0.1/15".parse().unwrap()];
    config.route.auto_route = true;
    config.route.route_address = vec![CAPTURED.parse().unwrap()];

    let mut instance = Instance::new(config, handler.clone()).expect("instance");
    instance.start(handler).expect("start");
    let added: Vec<String> = interfaces()
        .difference(&interfaces_before)
        .filter(|name| name.starts_with("utun"))
        .cloned()
        .collect();
    let [adapter] = added.as_slice() else {
        panic!("start adds exactly one utun, saw {added:?}");
    };
    let adapter = adapter.as_str();

    // The takeover: a lookup inside the captured prefix answers with
    // our adapter.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut owned = false;
    while Instant::now() < deadline {
        if route_names(ASK_ABOUT).is_some_and(|iface| iface == adapter) {
            owned = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(owned, "the captured prefix answers through {adapter}");

    // A bounded capture is only that prefix (sing-tun's
    // BuildAutoRouteRanges): no default route through the adapter, so
    // everything else keeps its route.
    assert_ne!(
        route_names(OUTSIDE).as_deref(),
        Some(adapter),
        "{OUTSIDE} must not answer through {adapter}"
    );
    assert_eq!(
        route_names(OUTSIDE),
        outside_before,
        "{OUTSIDE} kept its route"
    );
    let defaults = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .expect("netstat");
    let defaults = String::from_utf8_lossy(&defaults.stdout);
    assert!(
        !defaults
            .lines()
            .any(|l| l.starts_with("default") && l.split_whitespace().any(|f| f == adapter)),
        "no default route through {adapter}:\n{defaults}"
    );

    // The counters answer while the capture stands.
    assert_eq!(instance.stats().sessions_total, 0, "no sessions yet");

    // The teardown: an orderly shutdown returns the route table.
    instance.shutdown().expect("shutdown");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut gone = false;
    while Instant::now() < deadline {
        if route_names(ASK_ABOUT).is_none_or(|iface| iface != adapter) {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(gone, "the capture left with the instance");
}

/// Every interface name the system lists right now.
fn interfaces() -> BTreeSet<String> {
    let output = Command::new("ifconfig")
        .arg("-l")
        .output()
        .expect("ifconfig -l");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// Which interface the system's own reporter routes an address
/// through; None when no route answers.
fn route_names(address: &str) -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", address])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some("interface:"), Some(name)) => Some(name.to_string()),
            _ => None,
        }
    })
}

fn assert_root() {
    // SAFETY: geteuid has no preconditions.
    #[expect(unsafe_code)]
    let euid = unsafe { libc::geteuid() };
    assert_eq!(euid, 0, "this test edits the route table; it needs root");
}
