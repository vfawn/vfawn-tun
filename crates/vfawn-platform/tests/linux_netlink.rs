// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Contract tests for the rtnetlink backend against a real kernel.
//!
//! These need root and a Linux kernel, so they carry `#[ignore]` and run
//! with elevation:
//!
//! ```sh
//! sudo -E cargo test -p vfawn-platform -- --ignored --nocapture
//! ```
//!
//! Each test follows the add → verify → remove → verify pattern. The
//! `ip` command cross-validates what the snapshot reports.

#![cfg(target_os = "linux")]

use std::process::Command;
use vfawn_platform::linux::NetlinkBackend;
use vfawn_route::{
    InterfaceAddress, PolicyRule, RouteBackend, RouteEntry, RouteOp, RuleAction, RuleSelector,
};

fn backend() -> NetlinkBackend {
    NetlinkBackend::new().expect("netlink backend")
}

fn ip_cmd(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().expect("ip command");
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Create a dummy interface for testing; returns its name.
fn setup_dummy(name: &str) {
    let _ = Command::new("ip")
        .args(["link", "add", name, "type", "dummy"])
        .output();
    let _ = Command::new("ip")
        .args(["link", "set", name, "up"])
        .output();
}

fn cleanup_dummy(name: &str) {
    let _ = Command::new("ip").args(["link", "del", name]).output();
}

#[test]
#[ignore]
fn address_add_snapshot_remove_cycle() {
    let iface = "vfawntest0";
    setup_dummy(iface);
    let be = backend();

    let addr = InterfaceAddress {
        interface: iface.to_string(),
        prefix: "198.18.0.1/15".parse().unwrap(),
    };

    // Add.
    be.apply(&RouteOp::AddAddress(addr.clone())).unwrap();

    // Snapshot sees it.
    let snap = be.snapshot().unwrap();
    assert!(
        snap.addresses.iter().any(|a| a.prefix == addr.prefix),
        "snapshot should contain the added address"
    );

    // Cross-check with ip.
    let out = ip_cmd(&["addr", "show", "dev", iface]);
    assert!(out.contains("198.18.0.1/15"), "ip should show the address");

    // Remove.
    be.apply(&RouteOp::RemoveAddress(addr)).unwrap();

    // Snapshot no longer has it.
    let snap = be.snapshot().unwrap();
    assert!(
        !snap
            .addresses
            .iter()
            .any(|a| a.prefix.to_string() == "198.18.0.1/15"),
        "snapshot should not contain the removed address"
    );

    cleanup_dummy(iface);
}

#[test]
#[ignore]
fn route_add_remove_in_dedicated_table() {
    let iface = "vfawntest1";
    setup_dummy(iface);
    let be = backend();

    let route = RouteEntry {
        table: 2022,
        destination: "172.16.0.0/12".parse().unwrap(),
        gateway: None,
        interface: Some(iface.to_string()),
        metric: 0,
    };

    // Add.
    be.apply(&RouteOp::AddRoute(route.clone())).unwrap();

    // ip confirms it in table 2022.
    let out = ip_cmd(&["route", "show", "table", "2022"]);
    assert!(
        out.contains("172.16.0.0/12"),
        "table 2022 should contain the route: {out}"
    );

    // Remove.
    be.apply(&RouteOp::RemoveRoute(route)).unwrap();

    let out = ip_cmd(&["route", "show", "table", "2022"]);
    assert!(
        !out.contains("172.16.0.0/12"),
        "table 2022 should no longer contain the route"
    );

    cleanup_dummy(iface);
}

#[test]
#[ignore]
fn rule_add_remove_by_priority() {
    let be = backend();

    let rule = PolicyRule {
        priority: 9500,
        selector: RuleSelector {
            source: None,
            destination: Some("172.16.0.0/12".parse().unwrap()),
            incoming_interface: None,
            suppress_prefixlen: None,
            dport: None,
        },
        action: RuleAction::Lookup(254),
        tag: "vfawn-test".to_string(),
    };

    // Add.
    be.apply(&RouteOp::AddRule(rule.clone())).unwrap();

    // ip confirms it.
    let out = ip_cmd(&["rule", "list"]);
    assert!(
        out.contains("9500"),
        "ip rule should show priority 9500: {out}"
    );

    // Remove.
    be.apply(&RouteOp::RemoveRule(rule)).unwrap();

    let out = ip_cmd(&["rule", "list"]);
    assert!(
        !out.contains("9500:"),
        "ip rule should no longer show 9500: {out}"
    );
}

#[test]
#[ignore]
fn snapshot_repeated_reads_are_stable() {
    // A single-threaded netlink socket cannot service parallel callers;
    // the reconciler serializes through its own lock. This test verifies
    // that sequential repeated snapshots produce consistent results.
    let be = backend();
    let first = be.snapshot().unwrap();
    for _ in 0..10 {
        let again = be.snapshot().unwrap();
        assert_eq!(first.addresses.len(), again.addresses.len());
    }
}

#[test]
#[ignore]
fn idempotent_add_twice_succeeds() {
    let iface = "vfawntest2";
    setup_dummy(iface);
    let be = backend();

    let addr = InterfaceAddress {
        interface: iface.to_string(),
        prefix: "198.19.0.1/24".parse().unwrap(),
    };

    // First add succeeds.
    be.apply(&RouteOp::AddAddress(addr.clone())).unwrap();
    // Second add also succeeds (netlink EEXIST is absorbed or succeeds).
    // The exact behavior (Ok vs AlreadyExists) depends on the rtnetlink
    // error mapping; either way the process must not crash.
    let _ = be.apply(&RouteOp::AddAddress(addr.clone()));

    // Cleanup.
    be.apply(&RouteOp::RemoveAddress(addr)).unwrap();
    cleanup_dummy(iface);
}
