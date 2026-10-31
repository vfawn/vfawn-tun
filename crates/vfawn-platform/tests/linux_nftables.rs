// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Contract tests for the nftables rules backend against a real kernel.
//!
//! Run with elevation:
//!
//! ```sh
//! sudo -E cargo test -p vfawn-platform --test linux_nftables -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::process::Command;
use vfawn_platform::linux::NftablesBackend;

fn nft_list() -> String {
    let output = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .expect("nft command");
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
#[ignore]
fn table_lifecycle_create_verify_destroy() {
    let be = NftablesBackend::new("test0");

    // Clean slate.
    let _ = be.drop_table();

    // Create.
    be.ensure_table().unwrap();
    let out = nft_list();
    assert!(out.contains("vfawn_test0"), "table should exist: {out}");

    // Destroy.
    be.drop_table().unwrap();
    let out = nft_list();
    assert!(!out.contains("vfawn_test0"), "table should be gone: {out}");
}

#[test]
#[ignore]
fn dns_leak_rule_is_tagged_and_visible() {
    let be = NftablesBackend::new("test1");
    let _ = be.drop_table();
    be.ensure_table().unwrap();

    be.add_dns_leak_rule().unwrap();

    let out = nft_list();
    assert!(out.contains("udp dport 53"), "dport 53 rule: {out}");
    assert!(out.contains("vfawn-test1"), "tag present: {out}");

    be.drop_table().unwrap();
}

#[test]
#[ignore]
fn strict_route_block_is_tagged() {
    let be = NftablesBackend::new("test2");
    let _ = be.drop_table();
    be.ensure_table().unwrap();

    be.add_strict_route_block().unwrap();

    let out = nft_list();
    assert!(out.contains("meta nfproto ipv6"), "v6 block: {out}");
    assert!(out.contains("vfawn-test2"), "tag: {out}");

    be.drop_table().unwrap();
}

#[test]
#[ignore]
fn tagged_rules_detected_for_orphan_scan() {
    let be = NftablesBackend::new("test3");
    let _ = be.drop_table();
    be.ensure_table().unwrap();
    be.add_dns_leak_rule().unwrap();

    assert!(be.has_tagged_rules().unwrap());

    be.drop_table().unwrap();
    assert!(!be.has_tagged_rules().unwrap());

    // The global scanner also finds nothing.
    let orphans: Vec<String> = vfawn_platform::linux::nftables::find_vfawn_rules();
    assert!(
        orphans.is_empty() || !orphans.iter().any(|r| r.contains("vfawn_test3")),
        "no vfawn_test3 rules after cleanup: {orphans:?}"
    );
}

#[test]
#[ignore]
fn drop_table_is_idempotent() {
    let be = NftablesBackend::new("test4");
    be.drop_table().unwrap(); // non-existent
    be.drop_table().unwrap(); // still fine
    be.ensure_table().unwrap();
    be.drop_table().unwrap();
    be.drop_table().unwrap(); // already gone
}
