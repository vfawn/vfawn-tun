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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether the stacks terminate a packet at all: its destination must
/// be global unicast and not the device's own directed broadcast.
/// Multicast, broadcast, link-local, loopback and unspecified
/// destinations are the network's housekeeping (mDNS, SSDP, LLMNR,
/// DHCP); a stack that accepted them would hand them to a relay that
/// re-sends them, and the route that brought them here brings them
/// straight back. This is sing-tun's `dropNonUnicast`
/// (`stack_go_engine.go:782`, applied ahead of reassembly at :657),
/// with Go's `netip.Addr.IsGlobalUnicast` as the test.
///
/// A packet too short to name a destination passes: the parsers
/// downstream refuse it with their own reasons.
pub fn is_unicast_destination(packet: &[u8], broadcast: Option<Ipv4Addr>) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            Some(destination) != broadcast && is_global_unicast_v4(destination)
        }
        Some(6) if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            is_global_unicast_v6(Ipv6Addr::from(octets))
        }
        _ => true,
    }
}

fn is_global_unicast_v4(address: Ipv4Addr) -> bool {
    !(address.is_unspecified()
        || address.is_broadcast()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_link_local())
}

fn is_global_unicast_v6(address: Ipv6Addr) -> bool {
    // Go unmaps a v4-mapped address before judging it.
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_global_unicast_v4(mapped);
    }
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (address.segments()[0] & 0xffc0) == 0xfe80)
}

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
        // ICMP has no ports; the echo identifier gives the exchange
        // its key, so a ping's requests and its replies (same
        // identifier) hash to one slot. Other ICMP messages share the
        // zero identifier, which is exactly the "one datagram flow per
        // address pair" the datagram slot wants.
        IpProtocol::Icmp | IpProtocol::Icmpv6 => {
            let identifier =
                u16::from_be_bytes([*bytes.get(4).unwrap_or(&0), *bytes.get(5).unwrap_or(&0)]);
            (identifier, 0)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_to(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn v6_to(destination: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[24..40].copy_from_slice(&destination.octets());
        packet
    }

    #[test]
    fn the_network_housekeeping_is_not_terminated() {
        let broadcast = Some(Ipv4Addr::new(198, 19, 255, 255));
        for destination in [
            [224, 0, 0, 251],     // mDNS, the Windows soak's storm
            [239, 255, 255, 250], // SSDP
            [255, 255, 255, 255], // limited broadcast
            [198, 19, 255, 255],  // the device's directed broadcast
            [169, 254, 1, 1],     // link-local
            [127, 0, 0, 1],
            [0, 0, 0, 0],
        ] {
            assert!(
                !is_unicast_destination(&v4_to(destination), broadcast),
                "{destination:?} passed"
            );
        }
        for destination in ["ff02::fb", "fe80::1", "::1", "::", "::ffff:224.0.0.251"] {
            let address: Ipv6Addr = destination.parse().unwrap();
            assert!(
                !is_unicast_destination(&v6_to(address), broadcast),
                "{destination} passed"
            );
        }
    }

    #[test]
    fn unicast_is_terminated_private_ranges_included() {
        let broadcast = Some(Ipv4Addr::new(198, 19, 255, 255));
        // Go's IsGlobalUnicast keeps private and ULA addresses.
        for destination in [
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            [192, 168, 1, 1],
            [198, 18, 0, 2],
        ] {
            assert!(is_unicast_destination(&v4_to(destination), broadcast));
        }
        for destination in ["2606:4700::1", "fd00::1", "::ffff:1.1.1.1"] {
            let address: Ipv6Addr = destination.parse().unwrap();
            assert!(is_unicast_destination(&v6_to(address), broadcast));
        }
        // Without a known broadcast the directed one is not special.
        assert!(is_unicast_destination(&v4_to([198, 19, 255, 255]), None));
        // Too short to name a destination: the parsers decide.
        assert!(is_unicast_destination(&[0x45, 0, 0], broadcast));
    }
}
