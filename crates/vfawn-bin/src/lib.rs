// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Developer CLI, library half.
//!
//! Command implementations live in the library so the test harness and
//! examples can drive them without spawning a process; `main.rs` is a thin
//! argument parser on top.

pub mod bench;
pub mod up;

/// Placeholder for the rule cleanup tool.
pub fn cleanup() {
    println!("cleanup: not implemented yet; arrives with the route engine");
}
