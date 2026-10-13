// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! User-space TCP/IP termination.
//!
//! Two interchangeable backends sit behind features; both satisfy the same
//! `StackBackend` contract, so the host never needs to know which one is
//! compiled in:
//!
//! * `backend-ipstack`: drives the ipstack crate as the termination engine;
//! * `backend-native`: the in-tree stack derived from smoltcp's TCP core,
//!   reshaped around an accept queue and batched device I/O.
//!
//! Neither backend talks to the routing engine; stacks terminate flows, the
//! route engine owns the kernel state around them.
