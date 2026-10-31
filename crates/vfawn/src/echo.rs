// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A handler that echoes everything back, for tests, examples and the CLI.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use vfawn_core::{
    Action, FlowInfo, FlowTrackerHook, IcmpPacket, SessionHandler, TcpSession, UdpSession, Verdict,
};

/// Echoes TCP payloads back to the sender and bounces UDP datagrams to
/// their origin. Every accepted flow is counted.
pub struct EchoHandler;

impl EchoHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EchoHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-flow accounting the echo handler installs, so the host sees how the
/// tracker hook works without writing one.
pub struct EchoTracker {
    pub forward: AtomicU64,
    pub reverse: AtomicU64,
}

impl FlowTrackerHook for EchoTracker {
    fn count_forward(&self, n: u64) {
        self.forward.fetch_add(n, Ordering::Relaxed);
    }

    fn count_reverse(&self, n: u64) {
        self.reverse.fetch_add(n, Ordering::Relaxed);
    }

    fn established(&self) {}

    fn closed(&self, _reason: vfawn_core::CloseReason) {}
}

#[async_trait::async_trait]
impl SessionHandler for EchoHandler {
    fn judge_flow(&self, _flow: &FlowInfo, _first_packet: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        let mut buffer = [0u8; 16384];
        while let Ok(n) = session.read(&mut buffer).await
            && n > 0
        {
            let _ = session.write(&buffer[..n]).await;
        }
        let _ = session.shutdown_write().await;
    }

    async fn on_udp(&self, mut session: UdpSession) {
        let mut buffer = [0u8; 1500];
        while let Ok((n, remote)) = session.recv(&mut buffer).await {
            let _ = session.send(&buffer[..n], &remote).await;
        }
    }

    async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
        Action::Drop
    }
}

/// The same echo behavior, printing every flow to stdout as it arrives.
pub struct VerboseEchoHandler {
    flows: AtomicU64,
}

impl VerboseEchoHandler {
    pub fn new() -> Self {
        Self {
            flows: AtomicU64::new(0),
        }
    }

    pub fn flow_count(&self) -> u64 {
        self.flows.load(Ordering::Relaxed)
    }
}

impl Default for VerboseEchoHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SessionHandler for VerboseEchoHandler {
    fn judge_flow(&self, flow: &FlowInfo, _first_packet: &[u8]) -> Verdict {
        let n = self.flows.fetch_add(1, Ordering::Relaxed) + 1;
        println!(
            "[{:4}] flow #{}: {} {} -> {}",
            n,
            n,
            match flow.network {
                vfawn_core::Network::Tcp => "tcp",
                vfawn_core::Network::Udp => "udp",
                vfawn_core::Network::Icmp => "icmp",
                _ => "other",
            },
            flow.source,
            flow.destination,
        );
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        let flow = session.flow().clone();
        let tracker = Arc::new(EchoTracker {
            forward: AtomicU64::new(0),
            reverse: AtomicU64::new(0),
        });
        let t = tracker.clone();
        let mut buffer = [0u8; 16384];
        let mut total = 0u64;
        while let Ok(n) = session.read(&mut buffer).await
            && n > 0
        {
            total += n as u64;
            t.count_forward(n as u64);
            let _ = session.write(&buffer[..n]).await;
            t.count_reverse(n as u64);
        }
        let _ = session.shutdown_write().await;
        println!(
            "  closed: {} -> {} bytes={}",
            flow.source, flow.destination, total
        );
    }

    async fn on_udp(&self, mut session: UdpSession) {
        let flow = session.flow().clone();
        let mut buffer = [0u8; 1500];
        let mut total = 0u64;
        while let Ok((n, remote)) = session.recv(&mut buffer).await {
            total += n as u64;
            let _ = session.send(&buffer[..n], &remote).await;
        }
        println!(
            "  closed: {} -> {} bytes={}",
            flow.source, flow.destination, total
        );
    }

    async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
        Action::Drop
    }
}
