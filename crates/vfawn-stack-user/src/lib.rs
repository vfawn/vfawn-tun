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
pub mod accept;
#[cfg(feature = "backend-native")]
pub mod congestion;
#[cfg(feature = "backend-native")]
mod icmp;
#[cfg(feature = "backend-native")]
mod icmp_slot;
#[cfg(feature = "backend-native")]
pub mod native_backend;
#[cfg(feature = "backend-native")]
pub mod native_tcp;
#[cfg(feature = "backend-native")]
pub mod shards;
#[cfg(feature = "backend-native")]
pub mod udp_slot;

#[cfg(feature = "backend-ipstack")]
pub mod ipstack_backend;
#[cfg(feature = "backend-ipstack")]
pub mod ipstack_bridge;

#[cfg(feature = "backend-native")]
#[cfg(feature = "backend-native")]
pub use accept::{AcceptQueue, CookieSecret, FixedSecret};
#[cfg(feature = "backend-native")]
pub use congestion::{CongestionAlgo, Cubic, Reno, Signal};
#[cfg(feature = "backend-native")]
pub use icmp::{ECHO_REPLY, ECHO_REQUEST, IcmpTable, IcmpVerdict, TIME_EXCEEDED, UNREACHABLE};
#[cfg(feature = "backend-native")]
pub use icmp_slot::IcmpSlot;
#[cfg(feature = "backend-native")]
#[cfg(feature = "backend-native")]
pub mod splice_lane;
#[cfg(feature = "backend-ipstack")]
pub use ipstack_backend::IpstackBackend;
#[cfg(feature = "backend-native")]
pub use native_backend::NativeBackend;
#[cfg(feature = "backend-native")]
#[cfg(feature = "backend-native")]
pub use native_tcp::{Inbound, NativeTcpConnection, Reaction, ServerConnection, TcpState, emit_v4};
#[cfg(feature = "backend-native")]
#[cfg(feature = "backend-native")]
pub use shards::{ShardBell, ShardConfig, Shards, SlotLogic, UdpEcho};
#[cfg(all(feature = "backend-native", target_os = "linux"))]
pub use splice_lane::SpliceLane;
