// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Assembly entry point for embedding hosts.
//!
//! This crate wires a device, a stack backend and the route engine together
//! behind [`Instance`], so applications depend on a single crate instead of
//! composing the layers themselves. Feature flags decide which backends are
//! compiled in; the C ABI and the CLI binary are built on top of the same
//! assembly instead of duplicating it.
//!
//! # Minimal usage
//!
//! ```no_run
//! use std::sync::Arc;
//! use vfawn::echo::EchoHandler;
//! use vfawn::{Instance, VfawnConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let config = VfawnConfig::default();
//! let handler = Arc::new(EchoHandler);
//! let mut instance = Instance::new(config, handler.clone())?;
//! instance.start(handler)?;
//! // ... traffic flows; the handler sees every session ...
//! instance.shutdown()?;
//! # Ok(())
//! # }
//! ```

pub mod echo;
pub mod instance;

pub use instance::{Instance, RestartReason, StatsSnapshot};
pub use vfawn_core::{
    Action, CloseReason, ConfigError, DeviceCaps, DeviceConfig, DnsConfig, DnsMode, FlowInfo,
    FlowTrackerHook, IcmpPacket, MonitorEvent, Network, PacketDevice, SessionHandler, StackBackend,
    StackHandle, StackKind, StackPolicy, TcpSession, TcpTransport, UdpSession, UdpTransport,
    Verdict, VfawnConfig,
};
