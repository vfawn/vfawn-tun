// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The state model for declarative routing.
//!
//! Three kinds of kernel state, each with add and remove:
//! * addresses on the TUN interface;
//! * routes in the dedicated routing table;
//! * policy rules that direct traffic into that table.
//!
//! The desired state is what the host configured; the observed state is a
//! snapshot of what the kernel actually has. The planner is a pure
//! function that turns the gap between the two into an ordered list of
//! atomic operations, each carrying its own inverse so a failed apply
//! rolls back.

use ipnet::IpNet;
use std::net::IpAddr;

/// One address assigned to a network interface.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceAddress {
    pub interface: String,
    pub prefix: IpNet,
}

/// One route in a routing table.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteEntry {
    /// Which routing table this route lives in.
    pub table: u32,
    /// Destination prefix; a default route is 0.0.0.0/0 or ::/0.
    pub destination: IpNet,
    /// Next-hop address when the route is not directly connected.
    pub gateway: Option<IpAddr>,
    /// Outgoing interface for directly connected routes.
    pub interface: Option<String>,
    /// Lower is preferred.
    pub metric: u32,
}

/// What a policy rule does when it matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleAction {
    /// Send matching traffic to a specific routing table.
    Lookup(u32),
    /// Return unreachable to matching traffic (strict-route family blocks).
    Unreachable,
    /// Do nothing and continue to the next rule (exclusion bypass).
    Nop,
}

/// Which traffic a policy rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleSelector {
    /// Source prefix; None matches any source.
    pub source: Option<IpNet>,
    /// Destination prefix; None matches any destination.
    pub destination: Option<IpNet>,
    /// Incoming interface name; None matches any.
    pub incoming_interface: Option<String>,
    /// Suppress routes with a prefix length >= this value (suppresses
    /// the default route when 0).
    pub suppress_prefixlen: Option<u8>,
    /// Destination port (UDP); None matches any port. Only the nftables
    /// backend can express this; rtnetlink policy rules ignore it.
    pub dport: Option<u16>,
}

/// One policy rule: a priority-ordered match/action pair.
#[derive(Debug, Clone, Eq)]
pub struct PolicyRule {
    /// Lower numbers evaluate first.
    pub priority: u32,
    pub selector: RuleSelector,
    pub action: RuleAction,
    /// Tags identifying which instance created this rule; used for
    /// orphan detection on restart.
    pub tag: String,
}

/// Rule identity is priority, selector and action; the tag records who
/// created a rule for humans and scanners, and the kernel side of a
/// snapshot has no way to know it. Comparing tags would make every
/// observed rule unequal to its desired twin.
impl PartialEq for PolicyRule {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
            && self.selector == other.selector
            && self.action == other.action
    }
}

/// What the host wants the kernel to look like.
///
/// Derived from the `RouteConfig` section of `VfawnConfig`; the route
/// engine's job is to drive the kernel toward this shape and keep it
/// there through network changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredState {
    /// TUN interface name; routes and addresses reference this.
    pub interface_name: String,
    /// Addresses the TUN interface should carry.
    pub addresses: Vec<InterfaceAddress>,
    /// Routes that should exist in the dedicated table.
    pub routes: Vec<RouteEntry>,
    /// Policy rules that should exist, in priority order.
    pub rules: Vec<PolicyRule>,
    /// Prefixes that must never be captured (loopback, link-local,
    /// multicast, the host's own addresses).
    pub excluded: Vec<IpNet>,
    /// Dedicated routing table index (Linux default 2022).
    pub table_index: u32,
    /// Base priority for our policy rules (Linux default 9000).
    pub rule_index: u32,
}

impl DesiredState {
    /// The prefixes that are always excluded, regardless of
    /// configuration: loopback, link-local, and multicast ranges.
    pub fn default_exclusions() -> Vec<IpNet> {
        vec![
            "127.0.0.0/8".parse().unwrap(),
            "::1/128".parse().unwrap(),
            "169.254.0.0/16".parse().unwrap(),
            "fe80::/10".parse().unwrap(),
            "224.0.0.0/4".parse().unwrap(),
            "ff00::/8".parse().unwrap(),
        ]
    }
}

/// A snapshot of what the kernel currently has.
///
/// Produced by the platform backend's `snapshot()`; consumed by the
/// planner. This is pure data: the planner reasons about it without
/// touching the kernel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedState {
    pub addresses: Vec<InterfaceAddress>,
    pub routes: Vec<RouteEntry>,
    pub rules: Vec<PolicyRule>,
}

/// One atomic operation on kernel state.
///
/// Operations are ordered: the planner emits them in the sequence they
/// must execute. Each operation knows its own inverse, so a failed apply
/// undoes what already ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOp {
    AddAddress(InterfaceAddress),
    RemoveAddress(InterfaceAddress),
    AddRoute(RouteEntry),
    RemoveRoute(RouteEntry),
    AddRule(PolicyRule),
    RemoveRule(PolicyRule),
}

impl RouteOp {
    /// The operation that undoes this one.
    pub fn inverse(&self) -> RouteOp {
        match self {
            Self::AddAddress(a) => Self::RemoveAddress(a.clone()),
            Self::RemoveAddress(a) => Self::AddAddress(a.clone()),
            Self::AddRoute(r) => Self::RemoveRoute(r.clone()),
            Self::RemoveRoute(r) => Self::AddRoute(r.clone()),
            Self::AddRule(r) => Self::RemoveRule(r.clone()),
            Self::RemoveRule(r) => Self::AddRule(r.clone()),
        }
    }

    /// A human-readable description, for audit logs and dry-run reports.
    pub fn describe(&self) -> String {
        match self {
            Self::AddAddress(a) => format!("add address {} on {}", a.prefix, a.interface),
            Self::RemoveAddress(a) => format!("remove address {} from {}", a.prefix, a.interface),
            Self::AddRoute(r) => format!(
                "add route {} -> {:?} table {} metric {}",
                r.destination, r.gateway, r.table, r.metric
            ),
            Self::RemoveRoute(r) => {
                format!("remove route {} from table {}", r.destination, r.table)
            }
            Self::AddRule(r) => format!(
                "add rule prio {} {:?} -> {:?} [{}]",
                r.priority, r.selector.destination, r.action, r.tag
            ),
            Self::RemoveRule(r) => format!("remove rule prio {} [{}]", r.priority, r.tag),
        }
    }
}

/// A conflict the planner detected between the desired state and
/// something already in the kernel that this engine does not manage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub description: String,
}

/// An ordered list of operations plus any warnings the planner found.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub operations: Vec<RouteOp>,
    pub conflicts: Vec<Conflict>,
}

impl Plan {
    /// True when there is nothing to do.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// The operations that undo this entire plan, in reverse order.
    pub fn inverse(&self) -> Plan {
        Plan {
            operations: self.operations.iter().rev().map(RouteOp::inverse).collect(),
            conflicts: self.conflicts.clone(),
        }
    }

    /// A human-readable report; used by dry-run.
    pub fn describe(&self) -> String {
        let mut lines = Vec::new();
        if self.operations.is_empty() {
            lines.push("nothing to do; observed matches desired".to_string());
        } else {
            lines.push(format!("{} operations:", self.operations.len()));
            for (i, op) in self.operations.iter().enumerate() {
                lines.push(format!("  {:>3}. {}", i + 1, op.describe()));
            }
        }
        for conflict in &self.conflicts {
            lines.push(format!("conflict: {}", conflict.description));
        }
        lines.join("\n")
    }
}
