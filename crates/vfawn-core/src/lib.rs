// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Cross-layer contracts and the session dispatcher.
//!
//! Everything a backend needs in order to interoperate with the rest of the
//! library is defined here: [`PacketDevice`] for device I/O, [`StackBackend`]
//! for pluggable termination, and the [`SessionHandler`] verdict model that
//! gives the host final authority over every flow. The dispatcher that turns
//! device packets into sessions also lives in this crate, one layer above the
//! stacks it feeds.
//!
//! Two boundaries hold:
//!
//! * no platform APIs: platform specifics belong to `vfawn-platform`;
//! * no tokio: backends pick their own executor, and the data plane keeps
//!   deterministic threading of its own.
