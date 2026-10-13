// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Per-flow stack selection.
//!
//! Sends each flow to the user-space or the kernel backend according to the
//! configured rules (destination prefix, protocol, port, process identity).
//! This crate is glue by design: it owns the selection logic and holds no
//! stack semantics of its own.
