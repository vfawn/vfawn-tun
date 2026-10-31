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
use crate::model::{DesiredState, RouteOp};
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
    /// that already ran is undone in reverse order.
    pub fn apply(&self, desired: &DesiredState) -> Result<(), ReconcileError> {
        let observed = self
            .backend
            .snapshot()
            .map_err(|e| ReconcileError::SnapshotFailed(e.to_string()))?;

        let plan = planner::plan(desired, &observed);
        if plan.is_empty() {
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
            strict_route: false,
            dns_leak_prevention: false,
        })
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
