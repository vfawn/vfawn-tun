// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The contract between the route engine and the platform layer.
//!
//! The route crate owns the model and the planner; the platform crate
//! (Linux first, macOS and Windows later) implements this trait against
//! real kernel APIs. The trait stays narrow on purpose: snapshot, apply
//! one operation, and check whether an operation is already in effect.
//! Everything else (ordering, rollback, reconciliation) lives above, in
//! the engine.

use crate::model::{ObservedState, RouteOp};
use std::io;

/// Read and write kernel routing state.
///
/// Implementations must be idempotent: applying an operation that is
/// already in effect succeeds without change. This lets the reconciler
/// re-apply after a crash without tracking exactly where the previous
/// run stopped.
pub trait RouteBackend: Send + Sync {
    /// Read the current kernel state as pure data.
    fn snapshot(&self) -> io::Result<ObservedState>;

    /// Execute one atomic operation. Idempotent: applying twice is the
    /// same as applying once. Returns an error if the kernel rejects
    /// the operation.
    fn apply(&self, op: &RouteOp) -> io::Result<()>;

    /// Whether the effect of this operation is already present in the
    /// kernel. Used by dry-run to report what would actually change.
    fn is_in_effect(&self, op: &RouteOp) -> io::Result<bool>;
}

/// The interface an operation names no longer exists: the device was
/// removed underneath the capture. Carried inside an `io::Error` so a
/// backend can say so through the narrow trait above, and told apart
/// from every other `NotFound` (a netlink delete of an absent route
/// answers `ENOENT` too, which is not this).
#[derive(Debug)]
pub struct InterfaceGone(pub String);

impl std::fmt::Display for InterfaceGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "interface {} does not exist", self.0)
    }
}

impl std::error::Error for InterfaceGone {}

/// The error a backend answers when the interface it was told to use
/// is gone.
pub fn interface_gone(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, InterfaceGone(name.to_string()))
}

/// Whether `error` is a backend's [`interface_gone`].
pub fn is_interface_gone(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<InterfaceGone>())
}
