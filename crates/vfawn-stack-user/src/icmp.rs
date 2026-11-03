// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The ICMP layer: echo answered in place, error datagrams correlated
//! to the flow they report (RFC 792's types 0/8 for the answer path,
//! types 3/11 parsed for the embedded original header that names the
//! victim flow).
//!
//! The answer is built from the request's own bytes: identifier and
//! sequence stay (the pinging program's bookkeeping), the type flips
//! to 0, and the checksum is recomputed whole because the type byte
//! moved. The reply leaves toward the requester from the address the
//! request aimed at, with a TTL one lower than the request carried
//! (the answering hop is a router in the path's clothing, RFC 792's
//! spirit; a zero TTL on arrival means the packet already spent its
//! hop budget and gets silence, exactly as a router would).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use vfawn_core::{FlowInfo, IcmpPacket, Network};
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::protocol::IpProtocol;

/// Echo request (RFC 792).
pub const ECHO_REQUEST: u8 = 8;
/// Echo reply (RFC 792).
pub const ECHO_REPLY: u8 = 0;
/// Destination unreachable (RFC 792).
pub const UNREACHABLE: u8 = 3;
/// Time exceeded (RFC 792).
pub const TIME_EXCEEDED: u8 = 11;

/// How long an echo session stays counted after its last request.
const SESSION_LINGER: Duration = Duration::from_secs(30);

/// One tracked echo exchange: the requester, the probed address, and
/// the last time a request arrived. The correlator that reads these
/// fields (matching an error's quote to the ping that earned it)
/// arrives with the session surfaces; until then the table is the
/// accounting and the tests the reader.
#[derive(Debug, Clone)]
#[expect(dead_code)]
pub struct EchoSession {
    pub requester: SocketAddr,
    pub probed: std::net::IpAddr,
    pub identifier: u16,
    pub last_at: Instant,
}

/// The shared echo table: identifier+requester keyed, lingered out.
#[derive(Default)]
pub struct IcmpTable {
    sessions: Mutex<HashMap<(SocketAddr, u16), EchoSession>>,
}

impl IcmpTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one echo request; the table remembers the exchange so a
    /// later reply or error can be correlated, and drops entries whose
    /// linger expired while nobody was looking.
    pub fn on_echo_request(
        &self,
        requester: SocketAddr,
        probed: std::net::IpAddr,
        identifier: u16,
    ) {
        let mut sessions = self.sessions.lock().expect("icmp table");
        sessions.retain(|_, session| session.last_at.elapsed() <= SESSION_LINGER);
        sessions.insert(
            (requester, identifier),
            EchoSession {
                requester,
                probed,
                identifier,
                last_at: Instant::now(),
            },
        );
    }
}

/// What the ICMP layer learned from one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpVerdict {
    /// An echo request: answer with the built reply frame (IPv4
    /// packet toward the requester).
    EchoReply(Vec<u8>),
    /// An error datagram whose quoted header names this flow; the
    /// value is the ICMP code (unreachable subtype or 0 for time
    /// exceeded).
    ErrorFor(FlowInfo, u8),
    /// Nothing the layer acts on.
    Ignore,
}

/// Read one ICMP datagram and decide.
///
/// `packet` is the captured datagram with its flow (source = the
/// sender, destination = the address it aimed at); `payload` is the
/// ICMP message after the IP header.
impl From<&IcmpPacket> for IcmpVerdict {
    fn from(packet: &IcmpPacket) -> Self {
        classify(packet)
    }
}

pub fn classify(packet: &IcmpPacket) -> IcmpVerdict {
    match packet.kind() {
        ECHO_REQUEST => {
            let Some((identifier, _seq)) = echo_identity(packet.payload()) else {
                return IcmpVerdict::Ignore;
            };
            match build_echo_reply(packet, identifier) {
                Some(frame) => IcmpVerdict::EchoReply(frame),
                None => IcmpVerdict::Ignore,
            }
        }
        UNREACHABLE => {
            let (victim, code) = quoted_flow(packet.payload());
            (victim, code).into()
        }
        TIME_EXCEEDED => {
            let (victim, _) = quoted_flow(packet.payload());
            (victim, 0).into()
        }
        _ => IcmpVerdict::Ignore,
    }
}

impl From<(Option<FlowInfo>, u8)> for IcmpVerdict {
    fn from((victim, code): (Option<FlowInfo>, u8)) -> Self {
        match victim {
            Some(flow) => IcmpVerdict::ErrorFor(flow, code),
            None => IcmpVerdict::Ignore,
        }
    }
}

/// The echo identifier and sequence (RFC 792: the first four bytes of
/// the message). A datagram shorter than that is not an echo anything.
fn echo_identity(payload: &[u8]) -> Option<(u16, u16)> {
    if payload.len() < 8 {
        return None;
    }
    Some((
        u16::from_be_bytes([payload[4], payload[5]]),
        u16::from_be_bytes([payload[6], payload[7]]),
    ))
}

/// Build the echo reply: the request's IP and ICMP bytes with the type
/// flipped, the checksum recomputed, and the TTL spent by one hop.
///
/// The reply is assembled as a fresh IPv4 frame toward the requester
/// because the request's own header cannot just be reversed: its
/// options, if any, are the sender's business, and our answer carries
/// none.
fn build_echo_reply(packet: &IcmpPacket, _identifier: u16) -> Option<Vec<u8>> {
    let flow = packet.flow();
    let (src, dst) = match (flow.source.ip(), flow.destination.ip()) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => (src, dst),
        _ => return None, // the v4 frame builder is the volume-zero truth
    };
    let ttl = packet.ttl();
    if ttl == 0 {
        // The request spent its hop budget reaching us; a router would
        // answer time-exceeded with a quote, but a tunnel endpoint
        // that answers at all is lying about being a hop. Silence.
        return None;
    }
    let message = packet.payload();
    let mut replied = Vec::with_capacity(8 + message.len() - 8);
    replied.extend_from_slice(&message[..8]);
    replied[0] = ECHO_REPLY;
    replied[2..4].copy_from_slice(&[0, 0]); // checksum recomputed below
    replied.extend_from_slice(&message[8..]);
    let sum = vfawn_wire::checksum::sum_words(&replied);
    replied[2..4].copy_from_slice(&(!vfawn_wire::checksum::fold(sum)).to_be_bytes());
    Some(vfawn_wire::emit::ipv4_frame_v4(
        dst,
        src,
        IpProtocol::Icmp,
        ttl - 1,
        &replied,
    ))
}

/// Parse an error datagram's quoted original header (RFC 792: the
/// first eight bytes of the datagram that triggered the error, which
/// for IP begins with its own header). The flow inside names the
/// session the error closes.
fn quoted_flow(payload: &[u8]) -> (Option<FlowInfo>, u8) {
    if payload.len() < 8 + 20 {
        return (None, payload.get(1).copied().unwrap_or(0));
    }
    let quote = &payload[8..];
    let code = payload[1];
    let Ok((ip, _rest)) = Ipv4Header::parse(quote) else {
        return (None, code);
    };
    if ip.protocol != IpProtocol::Tcp && ip.protocol != IpProtocol::Udp {
        return (None, code);
    }
    let (src_port, dst_port) = udp_or_tcp_ports(quote, &ip);
    let source = std::net::SocketAddr::new(std::net::IpAddr::V4(ip.src), src_port);
    let destination = std::net::SocketAddr::new(std::net::IpAddr::V4(ip.dst), dst_port);
    let network = match ip.protocol {
        IpProtocol::Tcp => Network::Tcp,
        _ => Network::Udp,
    };
    (
        Some(FlowInfo {
            network,
            source,
            destination,
        }),
        code,
    )
}

/// The transport ports out of a quoted header, at the offset its own
/// protocol dictates.
fn udp_or_tcp_ports(quote: &[u8], ip: &Ipv4Header) -> (u16, u16) {
    let at = ip.header_len;
    let ports = quote.get(at..at + 4).unwrap_or(&[0, 0, 0, 0]);
    (
        u16::from_be_bytes([ports[0], ports[1]]),
        u16::from_be_bytes([ports[2], ports[3]]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn requester(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port))
    }

    #[test]
    fn echo_sessions_linger_then_die() {
        let table = IcmpTable::new();
        table.on_echo_request(
            requester(1),
            std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            7,
        );
        {
            let sessions = table.sessions.lock().expect("icmp table");
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions.values().next().expect("one").identifier, 7);
        }
        // Aged-out entries leave with the next request from anyone.
        let aged = EchoSession {
            requester: requester(1),
            probed: std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            identifier: 7,
            last_at: Instant::now() - SESSION_LINGER - Duration::from_secs(1),
        };
        table
            .sessions
            .lock()
            .expect("icmp table")
            .insert((requester(1), 7), aged);
        table.on_echo_request(
            requester(2),
            std::net::IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            8,
        );
        let sessions = table.sessions.lock().expect("icmp table");
        assert_eq!(sessions.len(), 1, "the stale exchange is gone");
        assert_eq!(sessions.values().next().expect("one").identifier, 8);
    }

    #[test]
    fn a_zero_ttl_echo_gets_silence() {
        let flow = FlowInfo {
            network: Network::Icmp,
            source: requester(1),
            destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 0)),
        };
        let mut message = vec![8u8, 0, 0, 0, 0, 1, 0, 1, b'x'];
        let sum = vfawn_wire::checksum::sum_words(&message);
        message[2..4].copy_from_slice(&(!vfawn_wire::checksum::fold(sum)).to_be_bytes());
        let packet = IcmpPacket::new(flow, 8, 0, message.into()).with_ttl(0);
        assert_eq!(
            classify(&packet),
            IcmpVerdict::Ignore,
            "a spent hop budget earns no answer"
        );
    }
}
