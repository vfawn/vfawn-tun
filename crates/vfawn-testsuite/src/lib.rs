// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Shared test utilities.
//!
//! An in-memory `PacketDevice`, pcap replay with an injectable clock, and
//! assertion helpers used across the integration suites. Consumed as a
//! dev-dependency so none of this code reaches the product dependency tree.

pub mod clock;
pub mod mock_device;
pub mod pcap_device;

pub use clock::{VirtualClock, WALL_CLOCK_TOLERANCE};
pub use mock_device::MockDevice;
pub use pcap_device::PcapDevice;
