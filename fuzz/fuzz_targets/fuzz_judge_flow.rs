// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The first-packet verdict path under hostile bytes: a flow identity
//! and a "first packet" that arbitrary input gets to shape, run through
//! a representative handler's synchronous verdict, the verdict executor,
//! and the RST and unreachable emitters. Constructing a reset from a
//! malformed or lying segment must be a packet or a refusal, never a
//! panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use vfawn_core::verdict::execute;
use vfawn_core::{
    CloseReason, CountingTracker, FlowInfo, FlowTrackerHook, IcmpPacket, Network, SessionHandler,
    TcpSession, UdpSession, Verdict,
};
use vfawn_wire::emit::{icmpv4_unreachable_v4, tcp_rst_teardown_v4, tcp_rst_v4};

struct Rules;
#[async_trait::async_trait]
impl SessionHandler for Rules {
    fn judge_flow(&self, flow: &FlowInfo, first_packet: &[u8]) -> Verdict {
        // The flavor of logic a real host writes, exercised on shapes
        // only the fuzzer would come up with.
        match flow.network {
            Network::Tcp if first_packet.len() > 20 => Verdict::AcceptWith {
                udp_timeout: None,
                tracker: Some(std::sync::Arc::new(CountingTracker::new(None))),
            },
            Network::Udp if flow.destination.port() == 53 => Verdict::Redirect(flow.destination),
            Network::Icmp => Verdict::Reject,
            Network::Tcp => Verdict::Reject,
            Network::Udp => Verdict::Drop,
            _ => Verdict::Drop,
        }
    }

    async fn on_tcp(&self, _session: TcpSession) {}
    async fn on_udp(&self, _session: UdpSession) {}
    async fn on_icmp(&self, _packet: IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

fuzz_target!(|data: &[u8]| {
    let flow = FlowInfo {
        network: match data.first().copied().unwrap_or(0) % 3 {
            0 => Network::Tcp,
            1 => Network::Udp,
            _ => Network::Icmp,
        },
        source: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, data.len().min(255) as u8, 7)),
            data.get(1).copied().map(u16::from).unwrap_or(0) * 256
                + data.get(2).copied().map(u16::from).unwrap_or(0),
        ),
        destination: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, data.first().copied().unwrap_or(1))),
            match data.first().copied().unwrap_or(0) % 3 {
                1 => 53,
                _ => 443,
            },
        ),
    };

    let verdict = Rules.judge_flow(&flow, data);
    let action = execute(verdict, &flow);
    match action {
        vfawn_core::VerdictAction::CreateSession { tracker, .. } => {
            if let Some(tracker) = tracker.as_ref() {
                tracker.count_forward(data.len() as u64);
                tracker.count_reverse(data.len() as u64);
                tracker.established();
                tracker.closed(CloseReason::Timeout);
            }
        }
        _ => {}
    }

    // Wire-level response construction from hostile input.
    if let Some(rst) = tcp_rst_v4(data, Ipv4Addr::LOCALHOST) {
        let _ = rst.len();
    }
    let code = data.first().copied().unwrap_or(3).min(15);
    if let Some(echo) = icmpv4_unreachable_v4(Ipv4Addr::LOCALHOST, data, code) {
        let _ = echo.len();
    }
    let teardown = tcp_rst_teardown_v4(
        std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
        std::net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 50000),
        u32::from(data.first().copied().unwrap_or(0)),
        u32::from(data.get(1).copied().unwrap_or(0)),
    );
    let _ = teardown.len();
});
