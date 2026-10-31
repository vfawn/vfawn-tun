// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Planner tests: the three properties (idempotency, completeness,
//! invertibility) plus specific scenarios.

use vfawn_route::*;

fn test_desired() -> DesiredState {
    desired_from_config(&RouteParams {
        interface: "tun0",
        addresses: &["198.18.0.1/15".parse().unwrap()],
        captured: &["198.18.0.0/15".parse().unwrap()],
        excluded: &["192.168.0.0/16".parse().unwrap()],
        table_index: 2022,
        rule_index: 9000,
        strict_route: true,
        dns_leak_prevention: true,
    })
}

fn addr(iface: &str, prefix: &str) -> InterfaceAddress {
    InterfaceAddress {
        interface: iface.to_string(),
        prefix: prefix.parse().unwrap(),
    }
}

fn route(table: u32, dest: &str, iface: &str) -> RouteEntry {
    RouteEntry {
        table,
        destination: dest.parse().unwrap(),
        gateway: None,
        interface: Some(iface.to_string()),
        metric: 0,
    }
}

fn rule(prio: u32, tag: &str) -> PolicyRule {
    PolicyRule {
        priority: prio,
        selector: RuleSelector {
            source: None,
            destination: None,
            incoming_interface: None,
            suppress_prefixlen: None,
            dport: None,
        },
        action: RuleAction::Lookup(2022),
        tag: tag.to_string(),
    }
}

// --- Property: idempotency ---

#[test]
fn empty_observed_yields_empty_plan_when_desired_matches() {
    let mut observed = ObservedState::default();
    let p = plan(&test_desired(), &observed);
    assert!(!p.is_empty());
    simulate_apply(&p, &mut observed);
    let second = plan(&test_desired(), &observed);
    assert!(second.is_empty(), "second plan after apply must be empty");
}

#[test]
fn plan_on_matching_state_is_empty() {
    let desired = test_desired();
    let observed = ObservedState {
        addresses: desired.addresses.clone(),
        routes: desired.routes.clone(),
        rules: desired.rules.clone(),
    };
    let p = plan(&desired, &observed);
    assert!(p.is_empty());
}

// --- Property: completeness (apply then re-plan is empty) ---

#[test]
fn applying_plan_makes_second_plan_empty() {
    let desired = test_desired();
    let mut observed = ObservedState::default();
    // Start with some stale state.
    observed.addresses.push(addr("tun0", "10.99.99.1/24"));
    observed.routes.push(route(2022, "10.99.99.0/24", "tun0"));
    observed.rules.push(rule(9050, "vfawn-stale"));

    let p = plan(&desired, &observed);
    assert!(!p.is_empty());
    simulate_apply(&p, &mut observed);
    let second = plan(&desired, &observed);
    assert!(second.is_empty());
}

// --- Property: invertibility (apply then inverse restores original) ---

#[test]
fn inverse_plan_restores_original_state() {
    let desired = test_desired();
    let original = ObservedState::default();
    let mut observed = original.clone();

    let p = plan(&desired, &observed);
    simulate_apply(&p, &mut observed);
    assert_ne!(observed, original);

    let inv = p.inverse();
    simulate_apply(&inv, &mut observed);
    // After inverse, the state matches what we started from (empty).
    assert_eq!(observed.addresses, original.addresses);
    assert_eq!(observed.routes, original.routes);
    assert_eq!(observed.rules, original.rules);
}

// --- Individual operations ---

#[test]
fn each_op_has_inverse() {
    let ops = vec![
        RouteOp::AddAddress(addr("tun0", "10.0.0.1/24")),
        RouteOp::RemoveAddress(addr("tun0", "10.0.0.1/24")),
        RouteOp::AddRoute(route(2022, "0.0.0.0/0", "tun0")),
        RouteOp::RemoveRoute(route(2022, "0.0.0.0/0", "tun0")),
        RouteOp::AddRule(rule(9000, "vfawn-test")),
        RouteOp::RemoveRule(rule(9000, "vfawn-test")),
    ];
    for op in &ops {
        let inv = op.inverse();
        let inv_inv = inv.inverse();
        assert_eq!(op, &inv_inv, "double inverse must be identity");
    }
}

// --- Addresses ---

#[test]
fn missing_address_is_added() {
    let desired = test_desired();
    let observed = ObservedState::default();
    let p = plan(&desired, &observed);
    assert!(
        p.operations
            .iter()
            .any(|op| matches!(op, RouteOp::AddAddress(_)))
    );
}

#[test]
fn stale_address_on_tun_is_removed() {
    let desired = test_desired();
    let mut observed = ObservedState::default();
    observed.addresses.push(addr("tun0", "10.99.99.1/24"));
    let p = plan(&desired, &observed);
    assert!(
        p.operations
            .iter()
            .any(|op| matches!(op, RouteOp::RemoveAddress(_))),
        "stale address on our interface should be removed"
    );
}

#[test]
fn address_on_other_interface_is_untouched() {
    let desired = test_desired();
    let mut observed = ObservedState::default();
    observed.addresses.push(addr("eth0", "192.168.1.1/24"));
    let p = plan(&desired, &observed);
    assert!(
        !p.operations
            .iter()
            .any(|op| matches!(op, RouteOp::RemoveAddress(_))),
        "addresses on other interfaces are not ours to manage"
    );
}

// --- Routes ---

#[test]
fn route_in_our_table_is_managed() {
    let desired = test_desired();
    let mut observed = ObservedState::default();
    observed.routes.push(route(2022, "172.16.0.0/12", "tun0"));
    let p = plan(&desired, &observed);
    assert!(
        p.operations
            .iter()
            .any(|op| matches!(op, RouteOp::RemoveRoute(_)))
    );
}

#[test]
fn route_in_main_table_is_untouched() {
    let desired = test_desired();
    let mut observed = ObservedState::default();
    observed.routes.push(route(254, "192.168.1.0/24", "eth0"));
    let p = plan(&desired, &observed);
    assert!(
        !p.operations
            .iter()
            .any(|op| matches!(op, RouteOp::RemoveRoute(_))),
        "routes in the main table are not ours"
    );
}

// --- Rules ---

#[test]
fn stale_tagged_rule_is_removed() {
    let desired = test_desired();
    let mut observed = ObservedState::default();
    observed.rules.push(rule(9050, "vfawn-old"));
    let p = plan(&desired, &observed);
    assert!(
        p.operations
            .iter()
            .any(|op| matches!(op, RouteOp::RemoveRule(_)))
    );
}

#[test]
fn untagged_rule_is_untouched() {
    let desired = test_desired();
    let mut observed = ObservedState::default();
    observed.rules.push(rule(8000, "system-managed"));
    let p = plan(&desired, &observed);
    assert!(
        !p.operations
            .iter()
            .any(|op| matches!(op, RouteOp::RemoveRule(_))),
        "rules without our tag are not ours"
    );
}

// --- Conflict detection ---

#[test]
fn priority_collision_with_foreign_rule_is_conflict() {
    let desired = test_desired();
    let mut observed = ObservedState::default();
    // A system rule at the exact priority we want to use.
    observed.rules.push(rule(desired.rule_index, "system-rule"));
    let p = plan(&desired, &observed);
    assert!(
        !p.conflicts.is_empty(),
        "expected a conflict on priority collision"
    );
}

// --- desired_from_config ---

#[test]
fn desired_from_config_has_expected_shape() {
    let d = test_desired();
    assert_eq!(d.interface_name, "tun0");
    assert_eq!(d.table_index, 2022);
    assert_eq!(d.rule_index, 9000);
    assert!(!d.addresses.is_empty());
    assert!(!d.routes.is_empty());
    assert!(!d.rules.is_empty());

    // Default exclusions are always present.
    assert!(d.excluded.iter().any(|e| e.to_string() == "127.0.0.0/8"));
    // Configured exclusions are merged in.
    assert!(d.excluded.iter().any(|e| e.to_string() == "192.168.0.0/16"));
}

#[test]
fn strict_route_adds_unreachable_rule() {
    let strict = desired_from_config(&RouteParams {
        interface: "t",
        addresses: &[],
        captured: &[],
        excluded: &[],
        table_index: 2022,
        rule_index: 9000,
        strict_route: true,
        dns_leak_prevention: false,
    });
    assert!(
        strict
            .rules
            .iter()
            .any(|r| r.action == RuleAction::Unreachable),
        "strict_route must add an unreachable rule"
    );
    let lax = desired_from_config(&RouteParams {
        interface: "t",
        addresses: &[],
        captured: &[],
        excluded: &[],
        table_index: 2022,
        rule_index: 9000,
        strict_route: false,
        dns_leak_prevention: false,
    });
    assert!(
        !lax.rules
            .iter()
            .any(|r| r.action == RuleAction::Unreachable),
        "strict_route=false must not add an unreachable rule"
    );
}

#[test]
fn dns_leak_prevention_adds_rule() {
    let with = desired_from_config(&RouteParams {
        interface: "t",
        addresses: &[],
        captured: &[],
        excluded: &[],
        table_index: 2022,
        rule_index: 9000,
        strict_route: false,
        dns_leak_prevention: true,
    });
    let without = desired_from_config(&RouteParams {
        interface: "t",
        addresses: &[],
        captured: &[],
        excluded: &[],
        table_index: 2022,
        rule_index: 9000,
        strict_route: false,
        dns_leak_prevention: false,
    });
    assert!(with.rules.len() > without.rules.len());
}

// --- Plan describe ---

#[test]
fn plan_describe_produces_readable_output() {
    let desired = test_desired();
    let observed = ObservedState::default();
    let p = plan(&desired, &observed);
    let text = p.describe();
    assert!(text.contains("operations:"));
    assert!(text.contains("add"));
}

#[test]
fn empty_plan_describes_nothing() {
    let p = Plan::default();
    let text = p.describe();
    assert!(text.contains("nothing to do"));
}

// --- Ordering ---

#[test]
fn rules_removed_before_addresses_added() {
    let desired = test_desired();
    let mut observed = ObservedState::default();
    observed.rules.push(rule(9050, "vfawn-stale"));
    observed.addresses.push(addr("tun0", "10.99.99.1/24"));

    let p = plan(&desired, &observed);
    let first_remove_idx = p
        .operations
        .iter()
        .position(|op| matches!(op, RouteOp::RemoveRule(_)))
        .expect("should have a rule removal");
    let first_add_addr_idx = p
        .operations
        .iter()
        .position(|op| matches!(op, RouteOp::AddAddress(_)))
        .expect("should have an address addition");
    assert!(
        first_remove_idx < first_add_addr_idx,
        "rules must be removed before addresses are added"
    );
}

#[test]
fn addresses_added_before_routes() {
    let desired = test_desired();
    let observed = ObservedState::default();
    let p = plan(&desired, &observed);
    let first_addr = p
        .operations
        .iter()
        .position(|op| matches!(op, RouteOp::AddAddress(_)))
        .expect("address addition");
    let first_route = p
        .operations
        .iter()
        .position(|op| matches!(op, RouteOp::AddRoute(_)))
        .expect("route addition");
    assert!(
        first_addr < first_route,
        "addresses must exist before routes reference the interface"
    );
}
