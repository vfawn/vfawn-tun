// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! User-space TCP/IP termination.
//!
//! Two interchangeable backends sit behind features; both satisfy the same
//! `StackBackend` contract, so the host never needs to know which one is
//! compiled in:
//!
//! * `backend-ipstack`: drives the ipstack crate as the termination engine;
//! * `backend-native`: the in-house TCP implementation, written from the
//!   RFCs on the shard model: an accept queue with cookies, batched device
//!   I/O as the native unit, and congestion control as a pluggable module.
//!
//! Neither backend talks to the routing engine; stacks terminate flows, the
//! route engine owns the kernel state around them.

#[cfg(feature = "backend-native")]
pub mod native_backend;
pub mod native_tcp;
#[cfg(feature = "backend-native")]
pub mod shards;

#[cfg(feature = "backend-ipstack")]
pub mod ipstack_backend;
#[cfg(feature = "backend-ipstack")]
pub mod ipstack_bridge;

#[cfg(feature = "backend-ipstack")]
pub use ipstack_backend::IpstackBackend;
#[cfg(feature = "backend-native")]
pub use native_backend::NativeBackend;
pub use native_tcp::{Inbound, NativeTcpConnection, Reaction, ServerConnection, TcpState, emit_v4};
#[cfg(feature = "backend-native")]
pub use shards::{ShardConfig, Shards, SlotLogic, UdpEcho};
