// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The per-app filter against the live kernel: uid-carrying rules
//! install through netlink, `ip rule` shows them with their ranges,
//! and an orderly remove leaves nothing. Root-gated like the other
//! contract tests.

#![cfg(target_os = "linux")]

use std::sync::Arc;
use vfawn_route::backend::RouteBackend;
use vfawn_route::model::{PolicyRule, RouteOp, RuleAction, RuleSelector};

fn backend() -> vfawn_platform::linux::NetlinkBackend {
    vfawn_platform::linux::NetlinkBackend::new().expect("netlink")
}

fn clean(priority: u32) {
    let b = backend();
    for rule in b.snapshot().expect("snapshot").rules {
        if rule.priority == priority {
            let _ = b.apply(&RouteOp::RemoveRule(rule));
        }
    }
}

#[test]
#[ignore]
fn uid_rules_install_and_show_their_ranges() {
    let b = backend();
    let priority = 9750;
    clean(priority);

    let rule = PolicyRule {
        priority,
        selector: RuleSelector {
            source: None,
            destination: Some("0.0.0.0/0".parse().unwrap()),
            incoming_interface: None,
            fwmark: None,
            suppress_prefixlen: None,
            dport: None,
            uid_range: Some(1000..=1999),
        },
        action: RuleAction::Lookup(2022),
        tag: "vfawn-uidlive".to_string(),
    };
    b.apply(&RouteOp::AddRule(rule.clone())).expect("add");

    // The system's own reporter names the range.
    let out = std::process::Command::new("ip")
        .args(["rule", "show"])
        .output()
        .expect("ip");
    let text = String::from_utf8_lossy(&out.stdout);
    let mine = text
        .lines()
        .find(|l| l.contains("9750"))
        .expect("our rule listed");
    assert!(
        mine.contains("uidrange 1000-1999"),
        "the range shows: {mine}"
    );
    assert!(mine.contains("lookup 2022"), "the table shows: {mine}");

    // And the snapshot reads it back with the same identity.
    let read = b
        .snapshot()
        .expect("snapshot")
        .rules
        .into_iter()
        .find(|r| r.priority == priority)
        .expect("snapshot sees it");
    assert_eq!(read.selector.uid_range, Some(1000..=1999));

    clean(priority);
    let gone = !b
        .snapshot()
        .expect("snapshot")
        .rules
        .iter()
        .any(|r| r.priority == priority);
    assert!(gone, "cleaned");
    let _ = Arc::new(());
}
