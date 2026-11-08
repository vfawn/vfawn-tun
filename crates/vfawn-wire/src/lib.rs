// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Packet-level primitives shared by every layer that must look inside a
//! packet.
//!
//! Header parsers and checksums are used from three directions at once: the
//! dispatcher (flow keys, DNS rewrite), the kernel NAT path (address
//! rewrite on the TUN write-back), and the user-space stack itself. Keeping
//! them in one zero-dependency crate means none of those layers has to
//! depend on any other.
//!
//! Parsers are strict by construction: malformed input is returned as an
//! error, never a panic. Everything arriving from a TUN device is untrusted
//! input, and parse paths must be safe to fuzz with arbitrary bytes.
//!
//! Field layouts follow RFC 791 (IPv4), RFC 8200 (IPv6 and its extension
//! headers), RFC 9293 (TCP), RFC 768 (UDP), RFC 792 (ICMPv4) and RFC 1071
//! (the internet checksum).

pub mod checksum;
pub mod emit;
pub mod error;
pub mod flow;
pub mod fragment_out;
pub mod icmpv4;
pub mod ipv4;
pub mod ipv6;
pub mod protocol;
pub mod tcp;
pub mod udp;

pub use emit::{icmpv4_unreachable_v4, tcp_rst_teardown_v4, tcp_rst_v4};
pub use error::ParseError;
pub use flow::{FlowKey, FragmentKey, flow_key, fragment_info};
pub use icmpv4::Icmpv4Header;
pub use ipv4::Ipv4Header;
pub use ipv6::{FragmentInfoV6, Ipv6Header, V6Payload};
pub use protocol::IpProtocol;
pub use tcp::{TcpFlags, TcpHeader};
pub use udp::UdpHeader;

/// The headroom every emitted frame carries: the virtio-net header's
/// ten bytes, zeroed. A device with virtio headers sends the frame as
/// it stands (the zero prefix is a valid no-offload header); a device
/// without them skips it. The emitters never look at it, and no
/// packet on the wire begins with a zero byte (the IP version nibble
/// is four or six), so the boundary sniffs for itself.
pub const VNET_HEADROOM: usize = 10;
