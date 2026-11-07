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
        if rule_belongs_to_capture(rule, desired) && !desired.rules.contains(rule) {
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
/// Whether an observed rule is this capture's to manage. The kernel
/// keeps no tags, so ownership is what the install shape implies. That
/// means our priority window plus either the dedicated table or an
/// exclusion nop; anything else in the window stays untouched.
fn rule_belongs_to_capture(rule: &PolicyRule, desired: &DesiredState) -> bool {
    let in_window = rule.priority >= desired.rule_index
        && rule.priority < desired.rule_index.saturating_add(64);
    let ours_shape = match rule.action {
        // The capture table and the main-table exclusions are the two
        // shapes the install creates; the window keeps both ours.
        RuleAction::Lookup(table) => table == desired.table_index || table == 254,
        RuleAction::Nop | RuleAction::Unreachable => true,
    };
    in_window && ours_shape
}

/// The tables that always route: the kernel's own. A rule selecting
/// one of these is never a black hole, whatever installed it.
const ALWAYS_LIVE_TABLES: [u32; 3] = [253, 254, 255];

/// Rules that select a table which no longer routes anywhere. A rule
/// outlives its instance because it points at a table, not a link:
/// the link's death reaps the table's routes and nothing reaps the
/// rule, which leaves it selecting an empty table — a black hole for
/// every packet it matches. A table is dead when no route in it rides
/// a live interface (the kernel keeps no tags; liveness of the table
/// is the whole signal a snapshot has).
pub fn orphan_rules(observed: &ObservedState) -> Vec<PolicyRule> {
    let live: std::collections::HashSet<&str> = observed
        .addresses
        .iter()
        .map(|address| address.interface.as_str())
        .chain(
            observed
                .routes
                .iter()
                .filter_map(|route| route.interface.as_deref()),
        )
        .collect();
    let mut live_tables: std::collections::HashSet<u32> =
        ALWAYS_LIVE_TABLES.iter().copied().collect();
    for route in &observed.routes {
        // A gateway route rides whatever the kernel resolves it to; a
        // pinned route rides its interface. Only a live ride keeps a
        // table alive.
        let rides_live = route
            .interface
            .as_deref()
            .is_none_or(|interface| live.contains(interface));
        if rides_live {
            live_tables.insert(route.table);
        }
    }
    observed
        .rules
        .iter()
        .filter(|rule| {
            matches!(
                rule.action,
                RuleAction::Lookup(table) if !live_tables.contains(&table)
            )
        })
        .cloned()
        .collect()
}

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
    /// The routing mark on this process's own sockets; zero disables
    /// the escape rule.
    pub mark: u32,
    pub strict_route: bool,
    pub dns_leak_prevention: bool,
    /// UID ranges to capture (Linux FRA_UID_RANGE): the per-app
    /// filter. Empty captures every UID, as before.
    pub include_uid: &'a [std::ops::RangeInclusive<u32>],
    /// UID ranges to spare even inside the capture. Applied ahead of
    /// the capture rules, toward the main table.
    pub exclude_uid: &'a [std::ops::RangeInclusive<u32>],
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
        include_uid,
        exclude_uid,
        table_index,
        rule_index,
        mark,
        strict_route,
        dns_leak_prevention,
        ..
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
    // One route per captured prefix, with the host bits masked away:
    // the model's IpNet tolerates them, kernels do not, and a
    // configuration that names the tunnel by its own address
    // ("198.18.0.1/15") is too natural to refuse at the door.
    for prefix in captured {
        routes.push(RouteEntry {
            table: table_index,
            destination: ipnet::IpNet::new(prefix.network(), prefix.prefix_len())
                .unwrap_or(*prefix),
            gateway: None,
            interface: Some(interface.to_string()),
            metric: 0,
        });
    }

    let tag = format!("vfawn-{}", interface);
    let mut rules = Vec::new();
    let mut priority = rule_index;

    // Step 0: the process's own escape. The dedicated table carries a
    // default route, so without this rule the very sockets that speak
    // for the tunnel are captured by the tunnel — their dials recurse
    // and die. Marked traffic answers to the main table before any
    // capture rule sees it, and the mark survives default-interface
    // changes a socket binding cannot.
    if mark != 0 {
        rules.push(PolicyRule {
            priority,
            selector: RuleSelector {
                destination: None,
                source: None,
                incoming_interface: None,
                fwmark: Some(mark),
                suppress_prefixlen: None,
                dport: None,
                uid_range: None,
            },
            action: RuleAction::Lookup(254),
            tag: tag.clone(),
        });
        priority += 1;
    }

    // Step 1: exclusion rules (bypass the dedicated table).
    for prefix in excluded {
        rules.push(PolicyRule {
            priority,
            selector: RuleSelector {
                destination: Some(*prefix),
                source: None,
                incoming_interface: None,
                fwmark: None,
                suppress_prefixlen: None,
                dport: None,
                uid_range: None,
            },
            // The main table, not "continue": a nop rule falls through
            // to the capture rule right below it, and the exclusion
            // would capture exactly what it exists to spare.
            action: RuleAction::Lookup(254),
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
                fwmark: None,
                suppress_prefixlen: None,
                dport: None,
                uid_range: None,
            },
            action: RuleAction::Unreachable,
            tag: tag.clone(),
        });
        priority += 1;
    }

    // Step 2.5: UID escapes ahead of the capture — a spared range
    // answers the main table no matter what the capture below would
    // do with its packets.
    for range in exclude_uid {
        rules.push(PolicyRule {
            priority,
            selector: RuleSelector {
                destination: None,
                source: None,
                incoming_interface: None,
                fwmark: None,
                suppress_prefixlen: None,
                dport: None,
                uid_range: Some(range.clone()),
            },
            action: RuleAction::Lookup(254),
            tag: tag.clone(),
        });
        priority += 1;
    }

    // Step 3: captured prefixes go to the dedicated table — every UID
    // when the filter is off, one rule per UID range when it is on
    // (the kernel matches one range per rule; segments are the honest
    // shape, the same one the reference stack installs).
    if include_uid.is_empty() {
        rules.push(PolicyRule {
            priority,
            selector: RuleSelector {
                destination: Some("0.0.0.0/0".parse().unwrap()),
                source: None,
                incoming_interface: None,
                fwmark: None,
                suppress_prefixlen: None,
                dport: None,
                uid_range: None,
            },
            action: RuleAction::Lookup(table_index),
            tag: tag.clone(),
        });
        priority += 1;
    } else {
        for range in include_uid {
            rules.push(PolicyRule {
                priority,
                selector: RuleSelector {
                    destination: Some("0.0.0.0/0".parse().unwrap()),
                    source: None,
                    incoming_interface: None,
                    fwmark: None,
                    suppress_prefixlen: None,
                    dport: None,
                    uid_range: Some(range.clone()),
                },
                action: RuleAction::Lookup(table_index),
                tag: tag.clone(),
            });
            priority += 1;
        }
    }

    // Step 4: suppress the default-route fallback in the main table.
    rules.push(PolicyRule {
        priority,
        selector: RuleSelector {
            destination: None,
            source: None,
            incoming_interface: None,
            fwmark: None,
            suppress_prefixlen: Some(0),
            dport: None,
            uid_range: None,
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
                fwmark: None,
                suppress_prefixlen: None,
                dport: Some(53),
                uid_range: None,
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
