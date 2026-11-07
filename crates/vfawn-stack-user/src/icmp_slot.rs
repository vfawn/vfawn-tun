// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The ICMP slot: datagrams the shard hands a home. TCP flows get the
//! state machine; an ICMP datagram gets this ,  parsed, judged, echoed
//! or correlated, and answered straight onto the wire. No connection,
//! no session thread, nothing to hold between packets except what the
//! [`IcmpTable`] remembers.

use bytes::BytesMut;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;

use vfawn_core::{FlowInfo, IcmpPacket, Network, SessionHandler, Verdict};
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::protocol::IpProtocol;

use crate::icmp::{ECHO_REQUEST, IcmpTable, IcmpVerdict};
use crate::shards::{BufferPool, SlotLogic};

/// The asking packet's hop budget, by family: one field, two homes.
fn hop_budget(packet: &[u8]) -> u8 {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => packet.get(8).copied().unwrap_or(0),
        Some(6) => packet.get(7).copied().unwrap_or(0),
        _ => 0,
    }
}

/// Everything an ICMP slot needs: the host's judgment, the echo
/// ledger, and the lane error reports ride to reach it (a session
/// thread per datagram would be absurd; the correlation lands on the
/// TCP sessions' close instead).
pub struct IcmpSlot {
    handler: Arc<dyn SessionHandler>,
    table: Arc<IcmpTable>,
    /// Where a correlated error's close directive travels: the same
    /// lane the shard's TCP slots would notify on, addressed by the
    /// victim flow so the owner can act.
    errors: SyncSender<FlowInfo>,
}

impl IcmpSlot {
    pub fn new(
        handler: Arc<dyn SessionHandler>,
        table: Arc<IcmpTable>,
        errors: SyncSender<FlowInfo>,
    ) -> Self {
        Self {
            handler,
            table,
            errors,
        }
    }
}

impl SlotLogic for IcmpSlot {
    fn on_packet(
        &mut self,
        packet: &[u8],
        out: &mut VecDeque<BytesMut>,
        _pool: &BufferPool,
        _mtu: usize,
    ) {
        // Both families' ICMP reaches here; the branch decides the
        // addresses and the rest is family-blind.
        let (flow, payload) = match packet.first().map(|byte| byte >> 4) {
            Some(4) => {
                let Ok((ip, payload)) = Ipv4Header::parse(packet) else {
                    return;
                };
                if ip.protocol != IpProtocol::Icmp || payload.len() < 8 {
                    return;
                }
                (
                    FlowInfo {
                        network: Network::Icmp,
                        source: std::net::SocketAddr::new(std::net::IpAddr::V4(ip.src), 0),
                        destination: std::net::SocketAddr::new(std::net::IpAddr::V4(ip.dst), 0),
                    },
                    payload,
                )
            }
            Some(6) => {
                let Ok((ip, rest)) = vfawn_wire::ipv6::Ipv6Header::parse(packet) else {
                    return;
                };
                let Ok(payload) = vfawn_wire::ipv6::V6Payload::walk(ip.next_header, rest) else {
                    return;
                };
                if payload.protocol != IpProtocol::Icmpv6 || payload.bytes.len() < 8 {
                    return;
                }
                (
                    FlowInfo {
                        network: Network::Icmp,
                        source: std::net::SocketAddr::new(std::net::IpAddr::V6(ip.src), 0),
                        destination: std::net::SocketAddr::new(std::net::IpAddr::V6(ip.dst), 0),
                    },
                    payload.bytes,
                )
            }
            _ => return,
        };
        // The host judges datagram flows once each; a datagram has no
        // handshake to defer to.
        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.handler.judge_flow(&flow, &[])
        }))
        .unwrap_or(Verdict::Drop);
        if !matches!(
            vfawn_core::verdict::execute(verdict, &flow),
            vfawn_core::verdict::VerdictAction::CreateSession { .. }
        ) {
            return;
        }
        let icmp = IcmpPacket::new(
            flow,
            payload[0],
            payload[1],
            bytes::Bytes::copy_from_slice(payload),
        )
        .with_ttl(hop_budget(packet));
        match crate::icmp::classify(&icmp) {
            IcmpVerdict::EchoReply(frame) => {
                if icmp.kind() == ECHO_REQUEST || icmp.kind() == crate::icmp::ECHO6_REQUEST {
                    self.table.on_echo_request(
                        icmp.flow().source,
                        icmp.flow().destination.ip(),
                        u16::from_be_bytes([payload[4], payload[5]]),
                    );
                }
                out.push_back(BytesMut::from(&frame[..]));
            }
            IcmpVerdict::ErrorFor(victim, _code) => {
                // The victim's session learns through the error lane;
                // the datagram itself is consumed here.
                let _ = self.errors.send(victim);
            }
            IcmpVerdict::Ignore => {}
        }
    }
}
