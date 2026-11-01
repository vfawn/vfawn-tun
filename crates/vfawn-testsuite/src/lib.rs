// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Shared test utilities.
//!
//! An in-memory `PacketDevice`, pcap replay with an injectable clock, a
//! fuzz injector, a pcap writer, and a loopback device: the tooling every
//! integration suite shares. Consumed as a dev-dependency so none of this
//! code reaches the product dependency tree.

pub mod clock;
pub mod diff;
pub mod diff_smoltcp;
pub mod fuzz_injector;
pub mod loopback;
pub mod mock_device;
pub mod pcap_device;
pub mod pcap_writer;
pub mod script;

pub use clock::{VirtualClock, WALL_CLOCK_TOLERANCE};
pub use fuzz_injector::FuzzInjector;
pub use loopback::Loopback;
pub use mock_device::MockDevice;
pub use pcap_device::PcapDevice;
pub use pcap_writer::{Direction, PcapWriter};
pub use script::{Script, reverse_tcp};
