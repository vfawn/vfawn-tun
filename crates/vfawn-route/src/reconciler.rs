// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The reconciler: drives the kernel toward the desired state, rolling
//! back on failure.
//!
//! The flow for every call is the same:
//!
//! 1. snapshot the kernel through the backend;
//! 2. plan the diff (the pure function from the planner module);
//! 3. apply each operation in order, recording its inverse;
//! 4. if any operation fails, execute the inverses in reverse order.
//!
//! When the rollback itself fails, the error carries the residual
//! operations so the caller (or the crash-safety scanner on restart)
//! knows what to clean up. Every applied, failed and rolled-back
//! operation lands in the audit log as one JSON line.

use crate::backend::RouteBackend;
use crate::model::{DesiredState, ObservedState, RouteOp};
use crate::planner;
use std::sync::Arc;
use std::sync::Mutex;

/// One audit entry, serialized as a JSON line.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    /// Unix epoch seconds.
    pub timestamp: u64,
    /// "apply" | "rollback" | "rollback_residual"
    pub phase: &'static str,
    /// The operation description.
    pub operation: String,
    /// "ok" | "error:<message>"
    pub outcome: String,
}

/// What went wrong during reconciliation.
#[derive(Debug)]
pub enum ReconcileError {
    /// The forward pass failed and the rollback restored the original
    /// state. Safe to retry.
    RolledBack { applied_count: usize, cause: String },
    /// The forward pass failed AND the rollback could not complete.
    /// Residual operations remain in the kernel; the crash-safety
    /// scanner should pick these up on restart.
    RollbackIncomplete {
        residuals: Vec<String>,
        cause: String,
    },
    /// The backend snapshot failed before any operations were attempted.
    SnapshotFailed(String),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RolledBack {
                applied_count,
                cause,
            } => write!(f, "applied {applied_count} ops then rolled back: {cause}"),
            Self::RollbackIncomplete { residuals, cause } => write!(
                f,
                "rollback incomplete ({} residuals): {cause}",
                residuals.len()
            ),
            Self::SnapshotFailed(c) => write!(f, "snapshot failed: {c}"),
        }
    }
}

impl std::error::Error for ReconcileError {}

/// Drives the backend toward the desired state.
pub struct Reconciler {
    backend: Arc<dyn RouteBackend>,
    audit: Mutex<Vec<AuditEntry>>,
}

impl Reconciler {
    pub fn new(backend: Arc<dyn RouteBackend>) -> Self {
        Self {
            backend,
            audit: Mutex::new(Vec::new()),
        }
    }

    /// Apply the desired state atomically. On failure, every operation
    /// that already ran is undone in reverse order. Rules whose
    /// instance is gone are swept first, best-effort: a dead hand's
    /// rule must not veto the living install.
    pub fn apply(&self, desired: &DesiredState) -> Result<(), ReconcileError> {
        let mut observed = self
            .backend
            .snapshot()
            .map_err(|e| ReconcileError::SnapshotFailed(e.to_string()))?;

        let swept = self.sweep_from(&mut observed);

        let plan = planner::plan(desired, &observed);
        if plan.is_empty() && swept == 0 {
            return Ok(());
        }

        // Forward pass.
        let mut applied: Vec<RouteOp> = Vec::with_capacity(plan.operations.len());
        for op in &plan.operations {
            match self.backend.apply(op) {
                Ok(()) => {
                    applied.push(op.clone());
                    self.log("apply", op, "ok");
                }
                Err(e) => {
                    self.log("apply", op, &format!("error:{e}"));
                    return self.rollback(applied, format!("{}: {e}", op.describe()));
                }
            }
        }
        Ok(())
    }

    /// Remove every rule whose instance is gone, against a fresh
    /// snapshot. Returns the rules it removed, for the caller's
    /// report.
    pub fn sweep_orphans(&self) -> Result<Vec<String>, ReconcileError> {
        let observed = self
            .backend
            .snapshot()
            .map_err(|e| ReconcileError::SnapshotFailed(e.to_string()))?;
        let removed = planner::orphan_rules(&observed)
            .into_iter()
            .map(|rule| RouteOp::RemoveRule(rule.clone()))
            .filter_map(|op| match self.backend.apply(&op) {
                Ok(()) => {
                    self.log("sweep", &op, "ok");
                    Some(op.describe())
                }
                Err(e) => {
                    self.log("sweep", &op, &format!("error:{e}"));
                    None
                }
            })
            .collect();
        Ok(removed)
    }

    /// Sweep against an already-taken snapshot, which this call also
    /// edits: what it removed must not survive into the plan's view,
    /// or the plan would see the rule as already in effect and skip
    /// re-adding it — an instance that swept its predecessor and then
    /// installed nothing. A failure to remove one orphan is logged
    /// and lived with — the rules this call could not take will meet
    /// this call again at the next pass, and their kernel state
    /// still matches what the plan sees.
    fn sweep_from(&self, observed: &mut ObservedState) -> usize {
        planner::orphan_rules(observed)
            .into_iter()
            .map(RouteOp::RemoveRule)
            .filter_map(|op| {
                let removed = match self.backend.apply(&op) {
                    Ok(()) => {
                        self.log("sweep", &op, "ok");
                        true
                    }
                    Err(e) => {
                        self.log("sweep", &op, &format!("error:{e}"));
                        false
                    }
                };
                removed.then_some(op)
            })
            .map(|op| {
                // Rule identity is priority, selector and action; the
                // tag only records who. Remove exactly what the kernel
                // just lost.
                if let RouteOp::RemoveRule(rule) = op {
                    observed.rules.retain(|existing| existing != &rule);
                }
            })
            .count()
    }

    /// Undo already-applied operations in reverse order.
    fn rollback(&self, applied: Vec<RouteOp>, cause: String) -> Result<(), ReconcileError> {
        let mut residuals = Vec::new();
        for op in applied.iter().rev() {
            let inverse = op.inverse();
            match self.backend.apply(&inverse) {
                Ok(()) => {
                    self.log("rollback", op, "ok");
                }
                Err(e) => {
                    self.log("rollback", op, &format!("error:{e}"));
                    residuals.push(format!("{} (rollback failed: {e})", op.describe()));
                }
            }
        }
        if residuals.is_empty() {
            Err(ReconcileError::RolledBack {
                applied_count: applied.len(),
                cause,
            })
        } else {
            for r in &residuals {
                self.log_raw("rollback_residual", r, "leftover");
            }
            Err(ReconcileError::RollbackIncomplete { residuals, cause })
        }
    }

    /// The audit trail as JSON lines.
    pub fn audit_jsonl(&self) -> String {
        let audit = self.audit.lock().unwrap();
        audit
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn log(&self, phase: &'static str, op: &RouteOp, outcome: &str) {
        self.log_raw(phase, &op.describe(), outcome);
    }

    fn log_raw(&self, phase: &'static str, description: &str, outcome: &str) {
        let entry = AuditEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            phase,
            operation: description.to_string(),
            outcome: outcome.to_string(),
        };
        self.audit.lock().unwrap().push(entry);
    }
}

/// Check whether two configurations differ only in hot-updatable fields.
/// Returns `None` when everything can be hot-applied, or the first
/// non-hot-updatable difference when a restart is needed.
pub fn needs_restart(old: &DesiredState, new: &DesiredState) -> Option<String> {
    if old.table_index != new.table_index {
        return Some(format!(
            "table_index {} -> {}",
            old.table_index, new.table_index
        ));
    }
    if old.rule_index != new.rule_index {
        return Some(format!(
            "rule_index {} -> {}",
            old.rule_index, new.rule_index
        ));
    }
    if old.interface_name != new.interface_name {
        return Some(format!(
            "interface {} -> {}",
            old.interface_name, new.interface_name
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A backend that records operations and can fail at a chosen step.
    struct MockBackend {
        state: Mutex<ObservedState>,
        calls: Mutex<Vec<String>>,
        fail_at: AtomicUsize,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                state: Mutex::new(ObservedState::default()),
                calls: Mutex::new(Vec::new()),
                fail_at: AtomicUsize::new(usize::MAX),
            }
        }

        fn fail_at_step(&self, n: usize) {
            self.fail_at.store(n, Ordering::SeqCst);
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl RouteBackend for MockBackend {
        fn snapshot(&self) -> io::Result<ObservedState> {
            Ok(self.state.lock().unwrap().clone())
        }

        fn apply(&self, op: &RouteOp) -> io::Result<()> {
            let n = self.calls.lock().unwrap().len();
            self.calls.lock().unwrap().push(op.describe());
            if n == self.fail_at.load(Ordering::SeqCst) {
                return Err(io::Error::other("injected failure"));
            }
            let mut state = self.state.lock().unwrap();
            planner::simulate_apply(
                &Plan {
                    operations: vec![op.clone()],
                    conflicts: Vec::new(),
                },
                &mut state,
            );
            Ok(())
        }

        fn is_in_effect(&self, op: &RouteOp) -> io::Result<bool> {
            let state = self.state.lock().unwrap();
            Ok(match op {
                RouteOp::AddAddress(a) | RouteOp::RemoveAddress(a) => state.addresses.contains(a),
                RouteOp::AddRoute(r) | RouteOp::RemoveRoute(r) => state.routes.contains(r),
                RouteOp::AddRule(r) | RouteOp::RemoveRule(r) => state.rules.contains(r),
            })
        }
    }

    fn test_desired() -> DesiredState {
        planner::desired_from_config(&planner::RouteParams {
            interface: "tun0",
            addresses: &["198.18.0.1/15".parse().unwrap()],
            captured: &["0.0.0.0/0".parse().unwrap()],
            excluded: &[],
            table_index: 2022,
            rule_index: 9000,
            mark: 0,
            bypass_mark: 0,
            capture_mark: 0,
            strict_route: false,
            dns_leak_prevention: false,
            include_uid: &[],
            exclude_uid: &[],
            include_interface: &[],
            exclude_interface: &[],
        })
    }

    #[test]
    fn apply_sweeps_a_dead_instances_rules_first() {
        let backend: Arc<MockBackend> = Arc::new(MockBackend::new());
        let re = Reconciler::new(backend.clone());
        let desired = test_desired();

        // A previous instance's rule still selects its table, whose
        // routes died with the old interface; the new instance's own
        // state matches desired so the plan alone would be empty.
        {
            let mut state = backend.state.lock().unwrap();
            state.rules.push(PolicyRule {
                priority: 9100,
                selector: RuleSelector {
                    source: None,
                    destination: None,
                    incoming_interface: None,
                    fwmark: None,
                    suppress_prefixlen: None,
                    dport: None,
                    uid_range: None,
                },
                action: RuleAction::Lookup(2077),
                tag: "vfawn-tun9".to_string(),
            });
            state.addresses.push(InterfaceAddress {
                interface: "tun0".to_string(),
                prefix: "198.18.0.1/15".parse().unwrap(),
            });
            state.routes.push(RouteEntry {
                table: 2022,
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: None,
                interface: Some("tun0".to_string()),
                metric: 0,
            });
            for rule in &desired.rules {
                state.rules.push(rule.clone());
            }
        }

        re.apply(&desired).unwrap();
        let calls = backend.calls.lock().unwrap().join(",");
        assert!(
            calls.contains("vfawn-tun9"),
            "the dead instance's rule must be swept, saw: {calls}"
        );
        let state = backend.state.lock().unwrap();
        assert!(
            !state.rules.iter().any(|r| r.tag == "vfawn-tun9"),
            "the swept rule is gone from the state"
        );
    }

    #[test]
    fn a_swept_predecessor_rule_is_readded_by_the_same_apply() {
        // The predecessor's rule has the same identity as the new
        // instance's own (same table, same shape; only the tag
        // differs) and its table is empty — the sweep takes it, and
        // the plan must see that and install its own copy, in the
        // same apply.
        let backend: Arc<MockBackend> = Arc::new(MockBackend::new());
        let re = Reconciler::new(backend.clone());
        let desired = test_desired();

        {
            let mut state = backend.state.lock().unwrap();
            state.addresses.push(InterfaceAddress {
                interface: "tun0".to_string(),
                prefix: "198.18.0.1/15".parse().unwrap(),
            });
            for rule in &desired.rules {
                let mut stale = rule.clone();
                stale.tag = "vfawn-gone0".to_string();
                state.rules.push(stale);
            }
            // No routes anywhere: every selector of the capture table
            // is a black hole until this install fills the table.
        }

        re.apply(&desired).unwrap();
        let state = backend.state.lock().unwrap();
        assert!(
            state
                .rules
                .iter()
                .any(|r| r.action == RuleAction::Lookup(2022)),
            "the capture rule exists after the apply that swept its predecessor"
        );
    }

    #[test]
    fn sweep_orphans_reports_what_it_took() {
        let backend: Arc<MockBackend> = Arc::new(MockBackend::new());
        let re = Reconciler::new(backend.clone());
        backend.state.lock().unwrap().rules.push(PolicyRule {
            priority: 9100,
            selector: RuleSelector {
                source: None,
                destination: None,
                incoming_interface: None,
                fwmark: None,
                suppress_prefixlen: None,
                dport: None,
                uid_range: None,
            },
            action: RuleAction::Lookup(2022),
            tag: "vfawn-gone0".to_string(),
        });

        let swept = re.sweep_orphans().unwrap();
        assert_eq!(swept.len(), 1, "one orphan, one report line");
        assert!(swept[0].contains("vfawn-gone0"));
    }

    #[test]
    fn apply_is_idempotent() {
        let backend: Arc<MockBackend> = Arc::new(MockBackend::new());
        let re = Reconciler::new(backend.clone());
        let desired = test_desired();

        re.apply(&desired).unwrap();
        let first_calls = backend.call_count();
        assert!(first_calls > 0);

        // Second apply should produce an empty plan (state already matches).
        re.apply(&desired).unwrap();
        assert_eq!(
            backend.call_count(),
            first_calls,
            "second apply should not execute any operations"
        );
    }

    #[test]
    fn failure_triggers_rollback() {
        let backend = Arc::new(MockBackend::new());
        backend.fail_at_step(2); // fail on the 3rd operation (0-indexed)
        let re = Reconciler::new(backend.clone());
        let desired = test_desired();

        let result = re.apply(&desired);
        assert!(result.is_err());

        // The error should be RolledBack, meaning the rollback succeeded.
        match result.unwrap_err() {
            ReconcileError::RolledBack { applied_count, .. } => {
                assert!(applied_count >= 2, "at least 2 ops applied before failure");
            }
            other => panic!("expected RolledBack, got {other:?}"),
        }

        // The backend state should be back to empty (rollback restored).
        let snap = backend.snapshot().unwrap();
        assert!(snap.addresses.is_empty());
        assert!(snap.routes.is_empty());
        assert!(snap.rules.is_empty());
    }

    #[test]
    fn audit_log_has_entries() {
        let backend = Arc::new(MockBackend::new());
        let re = Reconciler::new(backend);
        let desired = test_desired();

        re.apply(&desired).unwrap();
        let log = re.audit_jsonl();
        assert!(!log.is_empty());
        assert!(log.contains("\"phase\":\"apply\""));
    }

    #[test]
    fn needs_restart_detects_table_change() {
        let a = test_desired();
        let mut b = test_desired();
        b.table_index = 3000;
        assert!(needs_restart(&a, &b).is_some());
        // Same config: no restart needed.
        assert!(needs_restart(&a, &a).is_none());
    }
}
