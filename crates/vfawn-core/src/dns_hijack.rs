// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! DNS hijack: the stack-entry rewrite that turns "asked some resolver"
//! into "asked ours".
//!
//! In hijack mode every UDP or TCP segment addressed to port 53, on any
//! destination, is rewritten in flight toward the virtual resolver
//! address before the stack sees it; the host then receives a session
//! whose destination is the virtual address, and answers through it.
//! Replies leaving the stack carry the virtual address as their source,
//! which no client would accept: the engine maps each client flow back
//! to the destination it originally used and rewrites the source on the
//! way out, so the client's connected socket sees its answer coming from
//! the resolver it asked.
//!
//! The rewrite is incremental: only the replaced address field's delta
//! reaches the header and transport checksums, never a whole-packet
//! recomputation. The flow map is keyed by the client endpoint and
//! protocol; a client port re-asking a different resolver replaces its
//! own mapping, which matches how resolvers actually sequence queries.
//!
//! Scope, stated plainly: only plain DNS on port 53 crosses this path.
//! DNS over TLS (853) and DNS over HTTPS (443) are ordinary flows to
//! the stack, invisible to the rewrite, the same limitation the
//! reference stacks carry; enforcement belongs to route rules on those
//! ports, not here. IPv6 hijack needs a virtual address of its own; it
//! comes from explicit configuration, since a v6 prefix offers no
//! obvious neighbor-address convention worth inventing.

use crate::config::DnsConfig;
use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use vfawn_wire::checksum;
use vfawn_wire::flow::fragment_info;
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::ipv6::Ipv6Header;
use vfawn_wire::protocol::IpProtocol;
use vfawn_wire::tcp::TcpHeader;
use vfawn_wire::udp::UdpHeader;

/// When the flow map outgrows this, it empties. A lost mapping costs
/// one dropped reply and the client retries; a map without a cap costs
/// memory forever.
const MAP_CAPACITY: usize = 65536;

/// The rewrite engine for one direction pair. Shared between the
/// packet-in and packet-out paths of a stack, so the map lives behind
/// one lock, taken once per packet.
pub struct DnsHijack {
    virtual_v4: Option<Ipv4Addr>,
    virtual_v6: Option<Ipv6Addr>,
    /// Client endpoint and protocol to the destination it really used.
    flows: Mutex<HashMap<FlowKey, IpAddr>>,
    /// Mirror of the map's occupancy, maintained under the same lock and
    /// read without one: with no captured flows there is nothing any
    /// reply needs, and the per-packet parse in `restore` is pure cost.
    occupied: std::sync::atomic::AtomicUsize,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    client_ip: IpAddr,
    client_port: u16,
    protocol: IpProtocol,
}

/// What the inbound path did with one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HijackOutcome {
    /// The destination became the virtual resolver; a mapping exists.
    Hijacked,
    /// Nothing matched: no port-53 destination, no virtual address for
    /// this family, a fragment, or already pointed at the resolver.
    Untouched,
}

impl DnsHijack {
    /// An engine with explicit virtual addresses; `None` on a family
    /// disables the rewrite for that family.
    pub fn new(virtual_v4: Option<Ipv4Addr>, virtual_v6: Option<Ipv6Addr>) -> Self {
        Self {
            virtual_v4,
            virtual_v6,
            flows: Mutex::new(HashMap::new()),
            occupied: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// An engine from the DNS config and the interface prefixes.
    ///
    /// Hijack mode derives the virtual IPv4 address when the config
    /// lists none: the next address inside the interface's own prefix,
    /// stepping down instead when the interface address is the last one
    /// in it. Disabled and Native modes produce an inactive engine,
    /// which leaves every packet alone; their difference is interface
    /// DNS setup, which is platform policy, not packet surgery.
    pub fn from_config(config: &DnsConfig, inet4: &[Ipv4Net]) -> Self {
        if config.mode != crate::config::DnsMode::Hijack {
            return Self::new(None, None);
        }
        let mut virtual_v4 = None;
        let mut virtual_v6 = None;
        for address in &config.address {
            match address {
                IpAddr::V4(v4) => virtual_v4 = Some(*v4),
                IpAddr::V6(v6) => virtual_v6 = Some(*v6),
            }
        }
        if virtual_v4.is_none()
            && let Some(prefix) = inet4.first()
        {
            virtual_v4 = Some(derive_virtual_v4(*prefix));
        }
        Self::new(virtual_v4, virtual_v6)
    }

    /// Rewrite a packet entering the stack.
    pub fn hijack(&self, packet: &mut [u8]) -> HijackOutcome {
        match packet.first().copied().map(|b| b >> 4) {
            Some(4) => self.hijack_v4(packet),
            Some(6) => self.hijack_v6(packet),
            _ => HijackOutcome::Untouched,
        }
    }

    /// Rewrite a packet leaving the stack back toward the client.
    pub fn restore(&self, packet: &mut [u8]) -> bool {
        if self.occupied.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            // No hijacked flow has ever asked for its address back, so
            // no reply can need rewriting; skip the parse entirely.
            return false;
        }
        match packet.first().copied().map(|b| b >> 4) {
            Some(4) => self.restore_v4(packet),
            Some(6) => self.restore_v6(packet),
            _ => false,
        }
    }

    fn hijack_v4(&self, packet: &mut [u8]) -> HijackOutcome {
        let Some(resolver) = self.virtual_v4 else {
            return HijackOutcome::Untouched;
        };
        let (header, payload) = match Ipv4Header::parse(packet) {
            Ok(split) => split,
            Err(_) => return HijackOutcome::Untouched,
        };
        if fragment_info(packet).is_some() {
            // Fragments after the first carry no ports to judge by, and
            // rewriting only some fragments breaks reassembly.
            return HijackOutcome::Untouched;
        }
        let ports = match ports_of(header.protocol, payload) {
            Some(ports) => ports,
            None => return HijackOutcome::Untouched,
        };
        if ports.destination != 53 || header.dst == resolver {
            return HijackOutcome::Untouched;
        }

        let old_dst = header.dst.octets();
        let new_dst = resolver.octets();
        rewrite_v4(
            packet,
            header.header_len,
            &old_dst,
            &new_dst,
            header.protocol,
            false,
        );
        let key = FlowKey {
            client_ip: IpAddr::V4(header.src),
            client_port: ports.source,
            protocol: header.protocol,
        };
        self.remember(key, IpAddr::V4(header.dst));
        HijackOutcome::Hijacked
    }

    fn hijack_v6(&self, packet: &mut [u8]) -> HijackOutcome {
        let Some(resolver) = self.virtual_v6 else {
            return HijackOutcome::Untouched;
        };
        let (header, payload) = match Ipv6Header::parse(packet) {
            Ok(split) => split,
            Err(_) => return HijackOutcome::Untouched,
        };
        // The extension-header chain ends where the ports live; parsing
        // already walked it, and a chain that hides the transport from
        // us simply does not get hijacked.
        let Some(ports) = ports_of(header.next_header, payload) else {
            return HijackOutcome::Untouched;
        };
        if ports.destination != 53 || header.dst == resolver {
            return HijackOutcome::Untouched;
        }

        let old_dst = header.dst.octets();
        let new_dst = resolver.octets();
        rewrite_v6(packet, 40, &old_dst, &new_dst, header.next_header, false);
        let key = FlowKey {
            client_ip: IpAddr::V6(header.src),
            client_port: ports.source,
            protocol: header.next_header,
        };
        self.remember(key, IpAddr::V6(header.dst));
        HijackOutcome::Hijacked
    }

    fn restore_v4(&self, packet: &mut [u8]) -> bool {
        let Some(resolver) = self.virtual_v4 else {
            return false;
        };
        let (header, payload) = match Ipv4Header::parse(packet) {
            Ok(split) => split,
            Err(_) => return false,
        };
        if header.src != resolver {
            return false;
        }
        let Some(ports) = ports_of(header.protocol, payload) else {
            return false;
        };
        if ports.source != 53 {
            return false;
        }
        let key = FlowKey {
            client_ip: IpAddr::V4(header.dst),
            client_port: ports.destination,
            protocol: header.protocol,
        };
        let Some(original) = self.lookup(key) else {
            // The flow never needed rewriting: it asked the virtual
            // address to begin with, so the reply is already correct.
            return false;
        };
        let IpAddr::V4(original) = original else {
            return false;
        };
        let old_src = resolver.octets();
        let new_src = original.octets();
        rewrite_v4(
            packet,
            header.header_len,
            &old_src,
            &new_src,
            header.protocol,
            true,
        );
        true
    }

    fn restore_v6(&self, packet: &mut [u8]) -> bool {
        let Some(resolver) = self.virtual_v6 else {
            return false;
        };
        let (header, payload) = match Ipv6Header::parse(packet) {
            Ok(split) => split,
            Err(_) => return false,
        };
        if header.src != resolver {
            return false;
        }
        if !matches!(header.next_header, IpProtocol::Tcp | IpProtocol::Udp) {
            return false;
        }
        let Some(ports) = ports_of(header.next_header, payload) else {
            return false;
        };
        if ports.source != 53 {
            return false;
        }
        let key = FlowKey {
            client_ip: IpAddr::V6(header.dst),
            client_port: ports.destination,
            protocol: header.next_header,
        };
        let Some(original) = self.lookup(key) else {
            return false;
        };
        let IpAddr::V6(original) = original else {
            return false;
        };
        let old_src = resolver.octets();
        let new_src = original.octets();
        rewrite_v6(packet, 40, &old_src, &new_src, header.next_header, true);
        true
    }

    fn remember(&self, key: FlowKey, original: IpAddr) {
        let mut flows = self.flows.lock().expect("hijack flow map lock");
        if flows.len() >= MAP_CAPACITY {
            flows.clear();
        }
        flows.insert(key, original);
        self.occupied
            .store(flows.len(), std::sync::atomic::Ordering::Relaxed);
    }

    fn lookup(&self, key: FlowKey) -> Option<IpAddr> {
        self.flows
            .lock()
            .expect("hijack flow map lock")
            .get(&key)
            .copied()
    }
}

struct Ports {
    source: u16,
    destination: u16,
}

/// The port pair of a TCP or UDP payload; anything else has none.
fn ports_of(protocol: IpProtocol, payload: &[u8]) -> Option<Ports> {
    match protocol {
        IpProtocol::Tcp => {
            let (header, _) = TcpHeader::parse(payload).ok()?;
            Some(Ports {
                source: header.src_port,
                destination: header.dst_port,
            })
        }
        IpProtocol::Udp => {
            let (header, _) = UdpHeader::parse(payload).ok()?;
            Some(Ports {
                source: header.src_port,
                destination: header.dst_port,
            })
        }
        _ => None,
    }
}

/// Rewrite one address field of an IPv4 packet in place: the header
/// checksum and the transport checksum both see only the replaced
/// field's delta. An absent UDP checksum stays absent; nothing was
/// verified, so nothing needs fixing.
fn rewrite_v4(
    packet: &mut [u8],
    header_len: usize,
    old_field: &[u8; 4],
    new_field: &[u8; 4],
    protocol: IpProtocol,
    source_side: bool,
) {
    let address_at = if source_side { 12 } else { 16 };
    packet[address_at..address_at + 4].copy_from_slice(new_field);

    let header_checksum = u16::from_be_bytes([packet[10], packet[11]]);
    let fixed = checksum::adjust(header_checksum, old_field, new_field);
    packet[10..12].copy_from_slice(&fixed.to_be_bytes());

    // The transport checksum sits at a fixed offset in both TCP and
    // UDP headers.
    let transport_at = header_len
        + match protocol {
            IpProtocol::Tcp => 16,
            IpProtocol::Udp => 6,
            _ => return,
        };
    let Some(fixed_at) = packet.get_mut(transport_at..transport_at + 2) else {
        return;
    };
    let transport_checksum = u16::from_be_bytes([fixed_at[0], fixed_at[1]]);
    if protocol == IpProtocol::Udp && transport_checksum == 0 {
        return;
    }
    let fixed = checksum::adjust(transport_checksum, old_field, new_field);
    fixed_at.copy_from_slice(&fixed.to_be_bytes());
}

/// Rewrite one address field of an IPv6 packet in place at the given
/// transport offset; v6 carries no header checksum, only the transport
/// one moves.
fn rewrite_v6(
    packet: &mut [u8],
    transport_offset: usize,
    old_field: &[u8; 16],
    new_field: &[u8; 16],
    protocol: IpProtocol,
    source_side: bool,
) {
    let address_at = if source_side { 8 } else { 24 };
    packet[address_at..address_at + 16].copy_from_slice(new_field);

    let checksum_at = transport_offset
        + match protocol {
            IpProtocol::Tcp => 16,
            IpProtocol::Udp => 6,
            _ => return,
        };
    let Some(bytes) = packet.get_mut(checksum_at..checksum_at + 2) else {
        return;
    };
    let transport_checksum = u16::from_be_bytes([bytes[0], bytes[1]]);
    if protocol == IpProtocol::Udp && transport_checksum == 0 {
        return;
    }
    let fixed = checksum::adjust(transport_checksum, old_field, new_field);
    bytes.copy_from_slice(&fixed.to_be_bytes());
}

/// The next address after the interface's own inside its prefix,
/// stepping down when the interface address is the last one in it. On a
/// point-to-point prefix with no room at all, either neighbor works:
/// the virtual address exists only inside rewritten packets, never in
/// the kernel's routing.
pub fn derive_virtual_v4(prefix: Ipv4Net) -> Ipv4Addr {
    let addr = u32::from(prefix.addr());
    let up = addr + 1;
    if up < u32::from(prefix.broadcast()) {
        Ipv4Addr::from(up)
    } else {
        Ipv4Addr::from(addr - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv6Net;
    use vfawn_wire::checksum::{
        adjust, checksum as full_checksum, verify_transport_v4, verify_transport_v6,
    };

    const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const RESOLVER_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
    const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x10);
    const RESOLVER_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x53);

    fn udp_v4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20 + 8 + payload.len());
        let total = 20 + 8 + payload.len();
        packet.extend_from_slice(&[0x45, 0x00]);
        packet.extend_from_slice(&(total as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 1, 0, 0, 64, 17, 0, 0]);
        packet.extend_from_slice(&src.octets());
        packet.extend_from_slice(&dst.octets());
        packet.extend_from_slice(&sport.to_be_bytes());
        packet.extend_from_slice(&dport.to_be_bytes());
        packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(payload);
        let header_sum = full_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_sum.to_be_bytes());
        let transport = full_checksum(&packet[20..]);
        let pseudo =
            checksum::pseudo_header_v4(src, dst, IpProtocol::Udp, (8 + payload.len()) as u32);
        let sum = !fold(pseudo + sum_words_raw(&packet[20..]));
        packet[26..28].copy_from_slice(&sum.to_be_bytes());
        let _ = transport;
        packet
    }

    fn fold(mut sum: u32) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    fn sum_words_raw(data: &[u8]) -> u32 {
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        sum
    }

    #[test]
    fn adjust_matches_a_full_recompute() {
        // The incremental path must land exactly where recomputing the
        // whole region does, whatever else the region contains.
        let old = [0x08, 0x08, 0x08, 0x08u8];
        let new = [0xc6, 0x12, 0x00, 0x02u8];
        for filler in [
            [0u8; 8],
            [0xff; 8],
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            [0xde, 0xad, 0xbe, 0xef, 0, 0, 0x80, 0x01],
        ] {
            let mut region_old = old.to_vec();
            region_old.extend_from_slice(&filler);
            let whole = !fold(sum_words_raw(&region_old));
            let adjusted = adjust(whole, &old, &new);
            let mut region_new = new.to_vec();
            region_new.extend_from_slice(&filler);
            assert_eq!(
                adjusted,
                !fold(sum_words_raw(&region_new)),
                "filler {filler:?}"
            );
        }
    }

    #[test]
    fn udp53_hijack_rewrites_destination_and_fixes_checksums() {
        let engine = DnsHijack::new(Some(RESOLVER_V4), None);
        let mut packet = udp_v4(CLIENT_V4, Ipv4Addr::new(8, 8, 8, 8), 50000, 53, b"query");

        assert_eq!(engine.hijack(&mut packet), HijackOutcome::Hijacked);

        let (ip, payload) = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(ip.dst, RESOLVER_V4);
        assert_eq!(checksum::fold(checksum::sum_words(&packet[..20])), 0xffff);
        assert!(verify_transport_v4(
            ip.src,
            ip.dst,
            IpProtocol::Udp,
            payload
        ));
    }

    #[test]
    fn reply_from_the_virtual_address_returns_to_the_original() {
        let engine = DnsHijack::new(Some(RESOLVER_V4), None);
        let mut query = udp_v4(CLIENT_V4, Ipv4Addr::new(8, 8, 8, 8), 50000, 53, b"q");
        engine.hijack(&mut query);

        let mut reply = udp_v4(RESOLVER_V4, CLIENT_V4, 53, 50000, b"answer");
        assert!(engine.restore(&mut reply));

        let (ip, payload) = Ipv4Header::parse(&reply).unwrap();
        assert_eq!(
            ip.src,
            Ipv4Addr::new(8, 8, 8, 8),
            "the client asked 8.8.8.8"
        );
        assert!(verify_transport_v4(
            ip.src,
            ip.dst,
            IpProtocol::Udp,
            payload
        ));
    }

    #[test]
    fn flows_to_the_virtual_address_need_no_restore() {
        let engine = DnsHijack::new(Some(RESOLVER_V4), None);
        let mut direct = udp_v4(CLIENT_V4, RESOLVER_V4, 50000, 53, b"q");
        assert_eq!(engine.hijack(&mut direct), HijackOutcome::Untouched);

        let mut reply = udp_v4(RESOLVER_V4, CLIENT_V4, 53, 50000, b"a");
        assert!(!engine.restore(&mut reply), "no mapping, no rewrite");
        let (ip, _) = Ipv4Header::parse(&reply).unwrap();
        assert_eq!(ip.src, RESOLVER_V4);
    }

    #[test]
    fn other_ports_and_engines_pass_through() {
        let mut https = udp_v4(CLIENT_V4, Ipv4Addr::new(1, 1, 1, 1), 50000, 443, b"tls");
        let active = DnsHijack::new(Some(RESOLVER_V4), None);
        assert_eq!(active.hijack(&mut https), HijackOutcome::Untouched);

        let disabled = DnsHijack::new(None, None);
        let mut dns_packet = udp_v4(CLIENT_V4, Ipv4Addr::new(8, 8, 8, 8), 50000, 53, b"q");
        assert_eq!(disabled.hijack(&mut dns_packet), HijackOutcome::Untouched);
        let before = dns_packet.clone();
        let _ = disabled.restore(&mut dns_packet);
        assert_eq!(dns_packet, before);
    }

    #[test]
    fn v6_hijack_and_restore_round_trip() {
        let engine = DnsHijack::new(None, Some(RESOLVER_V6));
        let mut packet = udp_v6(
            CLIENT_V6,
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            50000,
            53,
            b"q",
        );

        assert_eq!(engine.hijack(&mut packet), HijackOutcome::Hijacked);
        let (ip, payload) = Ipv6Header::parse(&packet).unwrap();
        assert_eq!(ip.dst, RESOLVER_V6);
        assert!(verify_transport_v6(
            ip.src,
            ip.dst,
            IpProtocol::Udp,
            payload
        ));

        let mut reply = udp_v6(RESOLVER_V6, CLIENT_V6, 53, 50000, b"a");
        assert!(engine.restore(&mut reply));
        let (ip, payload) = Ipv6Header::parse(&reply).unwrap();
        assert_eq!(
            ip.src,
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)
        );
        assert!(verify_transport_v6(
            ip.src,
            ip.dst,
            IpProtocol::Udp,
            payload
        ));
    }

    fn udp_v6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(40 + 8 + payload.len());
        packet.extend_from_slice(&[0x60, 0, 0, 0]);
        packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.push(17);
        packet.push(64);
        packet.extend_from_slice(&src.octets());
        packet.extend_from_slice(&dst.octets());
        packet.extend_from_slice(&sport.to_be_bytes());
        packet.extend_from_slice(&dport.to_be_bytes());
        packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(payload);
        let pseudo =
            checksum::pseudo_header_v6(src, dst, IpProtocol::Udp, (8 + payload.len()) as u32);
        let sum = !fold(pseudo + sum_words_raw(&packet[40..]));
        packet[46..48].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    #[test]
    fn derivation_steps_up_inside_the_prefix() {
        let up = derive_virtual_v4("198.18.0.1/15".parse::<Ipv4Net>().unwrap());
        assert_eq!(up, Ipv4Addr::new(198, 18, 0, 2));
        let top = derive_virtual_v4("10.0.0.254/24".parse::<Ipv4Net>().unwrap());
        assert_eq!(top, Ipv4Addr::new(10, 0, 0, 253), "steps down at the top");
        let tiny = derive_virtual_v4("203.0.113.1/32".parse::<Ipv4Net>().unwrap());
        assert_eq!(tiny, Ipv4Addr::new(203, 0, 113, 0));
    }

    #[test]
    fn config_modes_build_the_right_engine() {
        let prefix = ["198.18.0.1/15".parse::<Ipv4Net>().unwrap()];

        let hijack_default = DnsConfig::default();
        let engine = DnsHijack::from_config(&hijack_default, &prefix);
        let mut packet = udp_v4(CLIENT_V4, Ipv4Addr::new(8, 8, 8, 8), 50000, 53, b"q");
        assert_eq!(engine.hijack(&mut packet), HijackOutcome::Hijacked);

        let disabled = DnsConfig {
            mode: crate::config::DnsMode::Disabled,
            ..DnsConfig::default()
        };
        let engine = DnsHijack::from_config(&disabled, &prefix);
        let mut packet = udp_v4(CLIENT_V4, Ipv4Addr::new(8, 8, 8, 8), 50000, 53, b"q");
        assert_eq!(engine.hijack(&mut packet), HijackOutcome::Untouched);

        let native = DnsConfig {
            mode: crate::config::DnsMode::Native,
            ..DnsConfig::default()
        };
        let engine = DnsHijack::from_config(&native, &prefix);
        let mut packet = udp_v4(CLIENT_V4, Ipv4Addr::new(8, 8, 8, 8), 50000, 53, b"q");
        assert_eq!(engine.hijack(&mut packet), HijackOutcome::Untouched);
        let _ = Ipv6Net::new(CLIENT_V6, 64);
    }
}
