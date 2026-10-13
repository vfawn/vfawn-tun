// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! C ABI surface.
//!
//! Handles instead of object references, generation-tagged slots so a stale
//! handle cannot alias a live one, every panic caught at the boundary and
//! translated to an error code, and configuration carried as versioned JSON
//! rather than mirrored structs. This crate translates; it does not decide
//! anything.
