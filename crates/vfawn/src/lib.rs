// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Assembly entry point for embedding hosts.
//!
//! This crate wires a device, a stack backend and the route engine together
//! behind [`Instance`], so applications depend on a single crate instead of
//! composing the layers themselves. Feature flags decide which backends are
//! compiled in; the C ABI and the CLI binary are built on top of the same
//! assembly instead of duplicating it.
