// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Flow identity extraction.
//!
//! The dispatcher pins a packet to a shard with the five-tuple. Later IP
//! fragments carry no ports, so they come back as `None` here and with an
//! identity from [`fragment_info`] instead, which is the slow-path
//! reassembly key: source, destination, protocol and fragment identifier
//! (RFC 791 §3.1 for IPv4, RFC 8200 §4.5 for IPv6).

use crate::ipv4::Ipv4Header;
use crate::ipv6::{Ipv6Header, V6Payload};
use crate::protocol::IpProtocol;
use crate::tcp::TcpHeader;
use crate::udp::UdpHeader;
use std::net::IpAddr;

/// The five-tuple of a TCP or UDP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: IpProtocol,
    pub src_port: u16,
    pub dst_port: u16,
}

/// The reassembly identity of a fragmented datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: IpProtocol,
    pub identification: u32,
}

/// Extract the flow key of a TCP or UDP packet.
///
/// Returns `None` for anything else: other protocols, later fragments, or
/// packets too short to carry ports. Callers that need to know why a
/// fragment got no key use [`fragment_info`].
pub fn flow_key(packet: &[u8]) -> Option<FlowKey> {
    match packet.first()? >> 4 {
        4 => {
            let (header, payload) = Ipv4Header::parse(packet).ok()?;
            if header.fragment_offset != 0 {
                return None;
            }
            transport_key(
                IpAddr::V4(header.src),
                IpAddr::V4(header.dst),
                header.protocol,
                payload,
            )
        }
        6 => {
            let (header, rest) = Ipv6Header::parse(packet).ok()?;
            let payload = V6Payload::walk(header.next_header, rest).ok()?;
            if let Some(fragment) = payload.fragment
                && fragment.offset != 0
            {
                return None;
            }
            transport_key(
                IpAddr::V6(header.src),
                IpAddr::V6(header.dst),
                payload.protocol,
                payload.bytes,
            )
        }
        _ => None,
    }
}

/// Extract the reassembly identity of a fragmented datagram.
///
/// Returns `None` for packets that are not fragments: IPv4 needs the More
/// Fragments flag or a nonzero offset, IPv6 needs a fragment header in the
/// chain.
pub fn fragment_info(packet: &[u8]) -> Option<FragmentKey> {
    match packet.first()? >> 4 {
        4 => {
            let (header, _) = Ipv4Header::parse(packet).ok()?;
            if header.more_fragments || header.fragment_offset != 0 {
                return Some(FragmentKey {
                    src: IpAddr::V4(header.src),
                    dst: IpAddr::V4(header.dst),
                    protocol: header.protocol,
                    identification: header.identification as u32,
                });
            }
            None
        }
        6 => {
            let (header, rest) = Ipv6Header::parse(packet).ok()?;
            let payload = V6Payload::walk(header.next_header, rest).ok()?;
            let fragment = payload.fragment?;
            if fragment.more || fragment.offset != 0 {
                return Some(FragmentKey {
                    src: IpAddr::V6(header.src),
                    dst: IpAddr::V6(header.dst),
                    protocol: payload.protocol,
                    identification: fragment.identification,
                });
            }
            None
        }
        _ => None,
    }
}

fn transport_key(src: IpAddr, dst: IpAddr, protocol: IpProtocol, bytes: &[u8]) -> Option<FlowKey> {
    let (src_port, dst_port) = match protocol {
        IpProtocol::Tcp => {
            let (header, _) = TcpHeader::parse(bytes).ok()?;
            (header.src_port, header.dst_port)
        }
        IpProtocol::Udp => {
            let (header, _) = UdpHeader::parse(bytes).ok()?;
            (header.src_port, header.dst_port)
        }
        _ => return None,
    };
    Some(FlowKey {
        src,
        dst,
        protocol,
        src_port,
        dst_port,
    })
}
