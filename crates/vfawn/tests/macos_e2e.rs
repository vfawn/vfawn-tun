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

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vfawn::echo::EchoHandler;
use vfawn::instance::Instance;
use vfawn_core::VfawnConfig;

/// The adapter is created under a fixed name so the route assertions
/// can name it.
const ADAPTER: &str = "utun9";

/// The prefix the capture owns, and an address inside it to ask the
/// route table about.
const CAPTURED: &str = "198.18.0.0/15";
const ASK_ABOUT: &str = "198.18.0.50";

#[test]
#[ignore]
fn takeover_stats_and_clean_teardown() {
    // Root: the route table edits need it.
    assert_root();

    let handler = Arc::new(EchoHandler::new());
    let mut config = VfawnConfig::default();
    config.device.name = Some(ADAPTER.to_string());
    config.device.mtu = 1500;
    config.device.inet4_address = vec!["198.18.0.1/15".parse().unwrap()];
    config.route.auto_route = true;
    config.route.route_address = vec![CAPTURED.parse().unwrap()];

    let mut instance = Instance::new(config, handler.clone()).expect("instance");
    instance.start(handler).expect("start");

    // The takeover: a lookup inside the captured prefix answers with
    // our adapter.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut owned = false;
    while Instant::now() < deadline {
        if route_names(ASK_ABOUT).is_some_and(|iface| iface == ADAPTER) {
            owned = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(owned, "the captured prefix answers through {ADAPTER}");

    // The counters answer while the capture stands.
    assert_eq!(instance.stats().sessions_total, 0, "no sessions yet");

    // The teardown: an orderly shutdown returns the route table.
    instance.shutdown().expect("shutdown");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut gone = false;
    while Instant::now() < deadline {
        if route_names(ASK_ABOUT).is_none_or(|iface| iface != ADAPTER) {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(gone, "the capture left with the instance");
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
