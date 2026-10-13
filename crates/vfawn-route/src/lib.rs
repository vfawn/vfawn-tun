// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Declarative routing.
//!
//! The engine models the desired kernel state, diffs it against an observed
//! snapshot, and applies the difference as an ordered sequence of atomic
//! operations, each one recording its inverse so a failed apply rolls back to
//! the previously good state. Applying the same desired state repeatedly is
//! idempotent, which is what makes crash recovery and network-change
//! reconciliation the same code path.
//!
//! Kernel manipulation happens exclusively through the [`RouteBackend`]
//! contract; implementations live in `vfawn-platform`, never here.
