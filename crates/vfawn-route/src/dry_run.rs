// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Report what a plan would do without touching the kernel.

use crate::model::{DesiredState, ObservedState};
use crate::planner;

/// Produce a human-readable dry-run report: what would change, what
/// stays, and any conflicts the planner found.
pub fn report(desired: &DesiredState, observed: &ObservedState) -> String {
    let plan = planner::plan(desired, observed);
    let mut lines = Vec::new();

    lines.push("dry-run report".to_string());
    lines.push("=".repeat(50).to_string());
    lines.push(format!(
        "interface: {}  table: {}  rule base: {}",
        desired.interface_name, desired.table_index, desired.rule_index
    ));
    lines.push(format!(
        "addresses desired: {}  observed: {}",
        desired.addresses.len(),
        observed
            .addresses
            .iter()
            .filter(|a| a.interface == desired.interface_name)
            .count()
    ));
    lines.push(format!(
        "routes in table:   desired: {}  observed: {}",
        desired.routes.len(),
        observed
            .routes
            .iter()
            .filter(|r| r.table == desired.table_index)
            .count()
    ));
    lines.push(format!(
        "rules (tagged):    desired: {}  observed: {}",
        desired.rules.len(),
        observed
            .rules
            .iter()
            .filter(|r| r.tag.starts_with("vfawn-"))
            .count()
    ));
    lines.push(String::new());
    lines.push(plan.describe());

    lines.join("\n")
}
