// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Shared test utilities.
//!
//! An in-memory `PacketDevice`, pcap replay with an injectable clock, and the
//! assertion helpers used across the integration suites. Consumed as a
//! dev-dependency so none of this code reaches the product dependency tree.
