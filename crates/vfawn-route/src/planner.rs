// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The pure-function diff: given what we want and what we have, produce
//! the ordered operations to close the gap.
//!
//! Three properties, all tested:
//!
//! * **Idempotency**: if observed already matches desired, the plan is
//!   empty.
//! * **Completeness**: after applying every operation, a second plan
//!   against the new state is empty.
//! * **Invertibility**: the inverse plan, applied after the forward plan,
//!   restores the original observed state.

use crate::model::*;
use ipnet::IpNet;

/// Compute the operations needed to get from `observed` to `desired`.
///
/// The ordering matters:
/// 1. Remove rules first (so stale selectors cannot capture traffic
///    during the transition).
/// 2. Remove routes that should not exist.
/// 3. Remove addresses that should not exist.
/// 4. Add addresses (the interface must have addresses before routes
///    reference it).
/// 5. Add routes.
/// 6. Add rules last (so rules only direct traffic once routes exist).
pub fn plan(desired: &DesiredState, observed: &ObservedState) -> Plan {
    let mut operations = Vec::new();
    let mut conflicts = Vec::new();

    // --- Rules: remove stale first, add new last ---
    for rule in &observed.rules {
        if rule.tag.starts_with("vfawn-") && !desired.rules.contains(rule) {
            operations.push(RouteOp::RemoveRule(rule.clone()));
        }
    }
    let new_rules: Vec<_> = desired
        .rules
        .iter()
        .filter(|r| !observed.rules.contains(r))
        .collect();
    // Check for priority collisions with rules we don't own.
    for rule in &new_rules {
        for existing in &observed.rules {
            if !existing.tag.starts_with("vfawn-") && existing.priority == rule.priority {
                conflicts.push(Conflict {
                    description: format!(
                        "rule priority {} already used by an unmanaged rule ({:?})",
                        rule.priority, existing.action
                    ),
                });
            }
        }
    }

    // --- Routes: remove stale first, add new after addresses ---
    for route in &observed.routes {
        if route.table == desired.table_index && !desired.routes.contains(route) {
            operations.push(RouteOp::RemoveRoute(route.clone()));
        }
    }
    let new_routes: Vec<_> = desired
        .routes
        .iter()
        .filter(|r| !observed.routes.contains(r))
        .collect();

    // --- Addresses: remove stale, add new before routes ---
    for addr in &observed.addresses {
        if addr.interface == desired.interface_name && !desired.addresses.contains(addr) {
            operations.push(RouteOp::RemoveAddress(addr.clone()));
        }
    }
    let new_addresses: Vec<_> = desired
        .addresses
        .iter()
        .filter(|a| !observed.addresses.contains(a))
        .collect();
    for addr in &new_addresses {
        operations.push(RouteOp::AddAddress((*addr).clone()));
    }

    // --- Add routes (after addresses exist) ---
    for route in &new_routes {
        operations.push(RouteOp::AddRoute((*route).clone()));
    }

    // --- Add rules (after routes exist) ---
    for rule in &new_rules {
        operations.push(RouteOp::AddRule((*rule).clone()));
    }

    Plan {
        operations,
        conflicts,
    }
}

/// Simulate applying a plan to an observed state; used by tests to
/// verify completeness and by dry-run to show what the outcome looks
/// like.
pub fn simulate_apply(plan: &Plan, observed: &mut ObservedState) {
    for op in &plan.operations {
        match op {
            RouteOp::AddAddress(a) => {
                observed.addresses.push(a.clone());
            }
            RouteOp::RemoveAddress(a) => {
                observed.addresses.retain(|x| x != a);
            }
            RouteOp::AddRoute(r) => {
                observed.routes.push(r.clone());
            }
            RouteOp::RemoveRoute(r) => {
                observed.routes.retain(|x| x != r);
            }
            RouteOp::AddRule(r) => {
                observed.rules.push(r.clone());
            }
            RouteOp::RemoveRule(r) => {
                observed.rules.retain(|x| x != r);
            }
        }
    }
}

/// Configuration parameters for building a desired state.
#[derive(Debug, Clone)]
pub struct RouteParams<'a> {
    pub interface: &'a str,
    pub addresses: &'a [IpNet],
    pub captured: &'a [IpNet],
    pub excluded: &'a [IpNet],
    pub table_index: u32,
    pub rule_index: u32,
    pub strict_route: bool,
    pub dns_leak_prevention: bool,
}

/// Build a desired state from the host configuration; this is the
/// entry point that connects `VfawnConfig` to the route engine.
///
/// The dedicated table gets a default route plus one route per captured
/// prefix. Policy rules follow the five-step pattern: exclusions bypass,
/// strict-route family blocks, captured-prefix lookups, suppress
/// default-route fallback, and DNS leak prevention.
pub fn desired_from_config(params: &RouteParams<'_>) -> DesiredState {
    let RouteParams {
        interface,
        addresses,
        captured,
        excluded,
        table_index,
        rule_index,
        strict_route,
        dns_leak_prevention,
    } = *params;
    let interface: &str = interface;
    let addresses: &[IpNet] = addresses;
    let captured: &[IpNet] = captured;
    let excluded: &[IpNet] = excluded;
    let addr_entries: Vec<_> = addresses
        .iter()
        .map(|p| InterfaceAddress {
            interface: interface.to_string(),
            prefix: *p,
        })
        .collect();

    let mut routes = Vec::new();
    // Default route in the dedicated table.
    routes.push(RouteEntry {
        table: table_index,
        destination: "0.0.0.0/0".parse().unwrap(),
        gateway: None,
        interface: Some(interface.to_string()),
        metric: 0,
    });
    // One route per captured prefix.
    for prefix in captured {
        routes.push(RouteEntry {
            table: table_index,
            destination: *prefix,
            gateway: None,
            interface: Some(interface.to_string()),
            metric: 0,
        });
    }

    let tag = format!("vfawn-{}", interface);
    let mut rules = Vec::new();
    let mut priority = rule_index;

    // Step 1: exclusion rules (bypass the dedicated table).
    for prefix in excluded {
        rules.push(PolicyRule {
            priority,
            selector: RuleSelector {
                destination: Some(*prefix),
                source: None,
                incoming_interface: None,
                suppress_prefixlen: None,
                dport: None,
            },
            action: RuleAction::Nop,
            tag: tag.clone(),
        });
        priority += 1;
    }

    // Step 2: strict-route family blocks (only when enabled).
    if strict_route {
        rules.push(PolicyRule {
            priority,
            selector: RuleSelector {
                destination: Some("::/0".parse().unwrap()),
                source: None,
                incoming_interface: None,
                suppress_prefixlen: None,
                dport: None,
            },
            action: RuleAction::Unreachable,
            tag: tag.clone(),
        });
        priority += 1;
    }

    // Step 3: captured prefixes go to the dedicated table.
    rules.push(PolicyRule {
        priority,
        selector: RuleSelector {
            destination: Some("0.0.0.0/0".parse().unwrap()),
            source: None,
            incoming_interface: None,
            suppress_prefixlen: None,
            dport: None,
        },
        action: RuleAction::Lookup(table_index),
        tag: tag.clone(),
    });
    priority += 1;

    // Step 4: suppress the default-route fallback in the main table.
    rules.push(PolicyRule {
        priority,
        selector: RuleSelector {
            destination: None,
            source: None,
            incoming_interface: None,
            suppress_prefixlen: Some(0),
            dport: None,
        },
        action: RuleAction::Lookup(table_index),
        tag: tag.clone(),
    });
    priority += 1;

    // Step 5: DNS leak prevention (port 53 to main table).
    if dns_leak_prevention {
        rules.push(PolicyRule {
            priority,
            selector: RuleSelector {
                destination: None,
                source: None,
                incoming_interface: None,
                suppress_prefixlen: None,
                dport: Some(53),
            },
            action: RuleAction::Lookup(254), // main table
            tag: tag.clone(),
        });
    }

    let mut all_excluded = DesiredState::default_exclusions();
    all_excluded.extend_from_slice(excluded);

    DesiredState {
        interface_name: interface.to_string(),
        addresses: addr_entries,
        routes,
        rules,
        excluded: all_excluded,
        table_index,
        rule_index,
    }
}
