// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The verdict on a TCP flow, taken before ipstack sees its SYN.
//!
//! ipstack answers a SYN with its own SYN-ACK the moment it accepts the
//! stream, and keeps the sequence state private; by the time a refused
//! flow reached the dispatch path, the client already held an open
//! connection that no reset we could build would match, so Reject
//! closed politely and the client timed out against silence. Judging
//! on the device side of the bridge, from the SYN's own bytes, lets the
//! reset follow RFC 9293 §3.4 exactly (`<SEQ=0><ACK=SEG.SEQ+1>
//! <CTL=RST,ACK>`) and keeps the SYN away from ipstack altogether.
//!
//! The accepting verdicts travel to the dispatch path through a small
//! table keyed by the flow's addresses, so the host is judged once per
//! flow and per-flow overrides (trackers, timeouts) survive the hop.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use vfawn_core::{FlowInfo, Network, SessionHandler, Verdict};
use vfawn_wire::{IpProtocol, Ipv4Header, Ipv6Header, TcpHeader, V6Payload};

/// Accepted verdicts waiting for their stream. ipstack accepts a SYN
/// within the same scheduling round, so the table stays near empty; the
/// cap bounds a SYN flood toward flows ipstack never accepts.
const HELD_CAP: usize = 4096;

/// A held verdict nobody claimed by now belongs to a SYN ipstack dropped.
const HELD_TTL: Duration = Duration::from_secs(30);

/// What the bridge does with one inbound packet.
pub enum GateOutcome {
    /// Hand the packet to ipstack.
    Pass,
    /// Discard it.
    Swallow,
    /// Discard it and write this frame back to the device instead.
    Answer(Vec<u8>),
}

/// The judge that runs on the bridge's reader thread.
pub struct SynGate {
    handler: Arc<dyn SessionHandler>,
    held: Mutex<HashMap<(SocketAddr, SocketAddr), (Verdict, Instant)>>,
}

impl SynGate {
    pub fn new(handler: Arc<dyn SessionHandler>) -> Self {
        Self {
            handler,
            held: Mutex::new(HashMap::new()),
        }
    }

    /// Judge `packet` if it opens a TCP flow; every other packet passes.
    pub fn inspect(&self, packet: &[u8]) -> GateOutcome {
        let Some((flow, reset_from)) = opening_syn(packet) else {
            return GateOutcome::Pass;
        };
        let key = (flow.source, flow.destination);
        // A retransmitted SYN of a flow already accepted: the host spoke
        // once, and ipstack owns the handshake from here.
        if self.lock().contains_key(&key) {
            return GateOutcome::Pass;
        }
        let judged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.handler.judge_flow(&flow, &[])
        }));
        let Ok(verdict) = judged else {
            eprintln!("judge_flow panicked for {flow:?}; flow dropped");
            return GateOutcome::Swallow;
        };
        match verdict {
            Verdict::Reject => match reset_for(packet, reset_from) {
                Some(reset) => GateOutcome::Answer(reset),
                None => GateOutcome::Swallow,
            },
            Verdict::Drop => GateOutcome::Swallow,
            accepted => {
                self.hold(key, accepted);
                GateOutcome::Pass
            }
        }
    }

    /// The verdict the gate took for this flow, if it took one. `None`
    /// means the SYN slipped past (a full table, a gate-less bridge) and
    /// the caller judges for itself.
    pub fn take(&self, source: SocketAddr, destination: SocketAddr) -> Option<Verdict> {
        self.lock()
            .remove(&(source, destination))
            .map(|(verdict, _)| verdict)
    }

    fn hold(&self, key: (SocketAddr, SocketAddr), verdict: Verdict) {
        let mut held = self.lock();
        if held.len() >= HELD_CAP {
            let now = Instant::now();
            held.retain(|_, (_, at)| now.duration_since(*at) < HELD_TTL);
        }
        // Still full of live entries: the flow is judged again at
        // dispatch, which costs a second callback, not correctness.
        if held.len() < HELD_CAP {
            held.insert(key, (verdict, Instant::now()));
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(SocketAddr, SocketAddr), (Verdict, Instant)>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The flow a pure SYN opens, plus the address its reset leaves from.
/// Later fragments, non-TCP and anything but a bare SYN answer `None`.
fn opening_syn(packet: &[u8]) -> Option<(FlowInfo, IpAddr)> {
    let (src, dst, segment) = match packet.first()? >> 4 {
        4 => {
            let (ip, payload) = Ipv4Header::parse(packet).ok()?;
            if ip.protocol != IpProtocol::Tcp || ip.fragment_offset != 0 {
                return None;
            }
            (IpAddr::V4(ip.src), IpAddr::V4(ip.dst), payload)
        }
        6 => {
            let (ip, rest) = Ipv6Header::parse(packet).ok()?;
            let payload = V6Payload::walk(ip.next_header, rest).ok()?;
            if payload.protocol != IpProtocol::Tcp {
                return None;
            }
            (IpAddr::V6(ip.src), IpAddr::V6(ip.dst), payload.bytes)
        }
        _ => return None,
    };
    let (tcp, _) = TcpHeader::parse(segment).ok()?;
    if !tcp.flags.is_syn() {
        return None;
    }
    let flow = FlowInfo {
        network: Network::Tcp,
        source: SocketAddr::new(src, tcp.src_port),
        destination: SocketAddr::new(dst, tcp.dst_port),
    };
    Some((flow, dst))
}

fn reset_for(syn: &[u8], from: IpAddr) -> Option<Vec<u8>> {
    match from {
        IpAddr::V4(from) => vfawn_wire::tcp_rst_v4(syn, from),
        IpAddr::V6(from) => vfawn_wire::emit::tcp_rst_v6(syn, from),
    }
}
