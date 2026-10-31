// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Cross-layer contracts and the session dispatcher.
//!
//! Everything a backend needs in order to interoperate with the rest of the
//! library is defined here: [`PacketDevice`] for device I/O, [`StackBackend`]
//! for pluggable termination, and the [`SessionHandler`] verdict model that
//! gives the host final authority over every flow.
//!
//! Two boundaries hold:
//!
//! * no platform APIs: platform specifics belong to `vfawn-platform`;
//! * no async runtime: backends pick their own executor, and the data plane
//!   keeps deterministic threading of its own.

pub mod config;
pub mod device;
pub mod monitor;
pub mod session;
pub mod stack;
pub mod verdict;

pub use config::{
    ConfigError, CongestionAlgo, DeviceConfig, DnsConfig, DnsMode, OffloadPolicy, OutboundFdHook,
    QueuePolicy, RouteConfig, RouteRule, StackConfig, StackPolicy, UdpNatConfig, UdpSessionMode,
    VfawnConfig,
};
pub use device::{DeviceCaps, PacketDevice};
pub use monitor::{MonitorEvent, StackKind};
pub use session::{
    Action, CloseReason, FlowInfo, FlowTrackerHook, IcmpPacket, Network, SessionHandler,
    TcpSession, TcpTransport, UdpSession, UdpTransport, Verdict,
};
pub use stack::{StackBackend, StackHandle};
pub use verdict::{CountingTracker, VerdictAction, execute};
