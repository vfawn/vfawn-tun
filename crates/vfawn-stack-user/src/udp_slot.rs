// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The UDP slot: a datagram flow's life inside a shard. The first
//! datagram of a flow earns a session (the same handler contract TCP
//! uses, [`SessionHandler::on_udp`]); subsequent datagrams deliver
//! through the session's channel; the host's replies ride a bounded
//! lane the packet path drains back onto the wire as whole IPv4
//! frames. No handshake, no sequence space — just the idle clock.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use vfawn_core::{FlowInfo, Network, SessionHandler, Verdict};
use vfawn_wire::checksum;
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::protocol::IpProtocol;
use vfawn_wire::udp::UdpHeader;

use crate::shards::{BufferPool, SlotLogic};

/// How much unsent host output one datagram flow may hold before the
/// next send waits: a burst of replies the wire cannot carry is
/// recent, not a stream to buffer (the cap is half the TCP lane's).
const LANE_CAP: usize = 128 * 1024;

/// How long a datagram flow lives after its last activity in either
/// direction (the default the contract's udp_timeout carries).
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// One datagram the host wrote, waiting for the wire.
pub struct PendingDatagram {
    data: Vec<u8>,
}

/// The UDP slot: parses the datagram, judges the flow on the first
/// packet, hands the session over, and frames the host's replies.
pub struct UdpSlot {
    handler: Arc<dyn SessionHandler>,
    sessions: SyncSender<UdpHandoff>,
    to_host: Option<tokio::sync::mpsc::UnboundedSender<HostEvent>>,
    lane: Arc<std::sync::Mutex<VecDeque<PendingDatagram>>>,
    lane_bytes: Arc<AtomicUsize>,
    judged: bool,
    flow: FlowInfo,
    /// The wire endpoints, as the emitter wants them (the captured
    /// flow's v4 addresses and ports — the reply leaves from the
    /// destination the datagram aimed at).
    client_addr: std::net::SocketAddrV4,
    server_addr: std::net::SocketAddrV4,
    last_active: Instant,
}

/// The session's event channel payload.
pub enum HostEvent {
    Datagram(Vec<u8>),
    Closed,
}

/// A ready UDP session handed to the runtime side.
pub struct UdpHandoff {
    pub flow: FlowInfo,
    pub events: tokio::sync::mpsc::UnboundedReceiver<HostEvent>,
    pub lane: Arc<std::sync::Mutex<VecDeque<PendingDatagram>>>,
    pub lane_bytes: Arc<AtomicUsize>,
    pub client_addr: std::net::SocketAddrV4,
    pub server_addr: std::net::SocketAddrV4,
}

impl UdpSlot {
    pub fn new(handler: Arc<dyn SessionHandler>, sessions: SyncSender<UdpHandoff>) -> Self {
        Self {
            handler,
            sessions,
            to_host: None,
            lane: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            lane_bytes: Arc::new(AtomicUsize::new(0)),
            judged: false,
            flow: FlowInfo {
                network: Network::Udp,
                source: SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                destination: SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    0,
                ),
            },
            client_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
            server_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
            last_active: Instant::now(),
        }
    }

    /// The host's say on the first datagram: the same verdict
    /// vocabulary TCP uses, with the same panic containment.
    fn judge(&mut self, ip: &Ipv4Header, udp: &UdpHeader) -> bool {
        self.judged = true;
        let source = SocketAddr::new(std::net::IpAddr::V4(ip.src), udp.src_port);
        let destination = SocketAddr::new(std::net::IpAddr::V4(ip.dst), udp.dst_port);
        self.flow = FlowInfo {
            network: Network::Udp,
            source,
            destination,
        };
        self.client_addr = std::net::SocketAddrV4::new(ip.src, udp.src_port);
        self.server_addr = std::net::SocketAddrV4::new(ip.dst, udp.dst_port);
        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.handler.judge_flow(&self.flow, &[])
        }))
        .unwrap_or(Verdict::Drop);
        matches!(
            vfawn_core::verdict::execute(verdict, &self.flow),
            vfawn_core::verdict::VerdictAction::CreateSession { .. }
        )
    }

    /// The session handoff: the channel pair and the lane, offered to
    /// the runtime side the moment the first datagram earned them.
    fn announce(&mut self) {
        if self.to_host.is_some() {
            return;
        }
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
        let handoff = UdpHandoff {
            flow: self.flow.clone(),
            events: event_rx,
            lane: Arc::clone(&self.lane),
            lane_bytes: Arc::clone(&self.lane_bytes),
            client_addr: self.client_addr,
            server_addr: self.server_addr,
        };
        if self.sessions.send(handoff).is_ok() {
            self.to_host = Some(event_tx);
        }
    }

    /// The host's datagrams, framed and handed to the out queue (the
    /// same exit the shard's TCP emissions use).
    fn drain_lane(&mut self, out: &mut VecDeque<BytesMut>) {
        let mut lane = self.lane.lock().expect("udp lane");
        while let Some(pending) = lane.pop_front() {
            self.lane_bytes
                .fetch_sub(pending.data.len(), AtomicOrdering::Relaxed);
            let Some(frame) = emit_udp_frame(
                *self.server_addr.ip(),
                *self.client_addr.ip(),
                self.server_addr.port(),
                self.client_addr.port(),
                &pending.data,
            ) else {
                continue;
            };
            out.push_back(BytesMut::from(&frame[..]));
        }
    }
}

impl SlotLogic for UdpSlot {
    fn on_packet(
        &mut self,
        packet: &[u8],
        out: &mut VecDeque<BytesMut>,
        _pool: &BufferPool,
        _mtu: usize,
    ) {
        self.last_active = Instant::now();
        let Ok((ip, rest)) = Ipv4Header::parse(packet) else {
            return;
        };
        if ip.protocol != IpProtocol::Udp {
            return;
        }
        let Ok((udp, datagram)) = UdpHeader::parse(rest) else {
            return;
        };
        if !self.judged && !self.judge(&ip, &udp) {
            return;
        }
        // The first accepted datagram earns the session before it
        // delivers: the host sees the flow as live, then the bytes.
        self.announce();
        // The lane drains before the delivery: the host's reply to the
        // PREVIOUS datagram leaves before this one's session write has
        // a chance to reorder against it.
        self.drain_lane(out);
        if let Some(to_host) = &self.to_host
            && !datagram.is_empty()
        {
            let _ = to_host.send(HostEvent::Datagram(datagram.to_vec()));
        }
    }

    fn timer_wanted(&self) -> Option<Duration> {
        Some((self.last_active + IDLE_TIMEOUT).saturating_duration_since(Instant::now()))
    }

    fn on_timer(&mut self, out: &mut VecDeque<BytesMut>, _pool: &BufferPool) {
        if self.last_active.elapsed() >= IDLE_TIMEOUT {
            if let Some(to_host) = &self.to_host {
                let _ = to_host.send(HostEvent::Closed);
            }
            return;
        }
        // The idle sweep also drains the lane: the host's last reply
        // before a quiet spell still reaches the wire.
        self.drain_lane(out);
    }

    fn on_idle(&mut self, out: &mut VecDeque<BytesMut>) {
        self.drain_lane(out);
    }
}

/// Build a whole IPv4+UDP frame from the addresses and datagram.
pub fn emit_udp_frame(
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    data: &[u8],
) -> Option<Vec<u8>> {
    if data.len() > (u16::MAX - 8) as usize {
        return None;
    }
    let length = 8u16.checked_add(data.len() as u16)?;
    let mut udp = Vec::with_capacity(8 + data.len());
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&length.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(data);
    let sum = checksum::pseudo_header_v4(src, dst, IpProtocol::Udp, udp.len() as u32)
        + checksum::sum_words(&udp);
    let folded = !checksum::fold(sum);
    udp[6..8].copy_from_slice(&folded.to_be_bytes());

    let frame = vfawn_wire::emit::ipv4_frame_v4(src, dst, IpProtocol::Udp, 64, &udp);
    Some(frame)
}

/// The session-facing transport: host reads pull datagrams from the
/// slot's channel; host sends push into the lane the slot frames.
pub struct NativeUdpIo {
    pub events: tokio::sync::mpsc::UnboundedReceiver<HostEvent>,
    pub lane: Arc<std::sync::Mutex<VecDeque<PendingDatagram>>>,
    pub lane_bytes: Arc<AtomicUsize>,
    pub origin: SocketAddr,
}

#[async_trait::async_trait]
impl vfawn_core::UdpTransport for NativeUdpIo {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.events.recv().await {
            Some(HostEvent::Datagram(data)) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok((n, self.origin))
            }
            Some(HostEvent::Closed) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "udp session closed",
            )),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "udp session gone",
            )),
        }
    }

    async fn send(&mut self, data: &[u8], _to: &SocketAddr) -> io::Result<()> {
        while self.lane_bytes.load(AtomicOrdering::Relaxed) + data.len() > LANE_CAP {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let mut lane = self.lane.lock().expect("udp lane");
        self.lane_bytes
            .fetch_add(data.len(), AtomicOrdering::Relaxed);
        lane.push_back(PendingDatagram {
            data: data.to_vec(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_udp_frame_builds_with_sane_lengths() {
        let frame = emit_udp_frame(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            53,
            5353,
            b"payload",
        )
        .expect("frame");
        assert_eq!(frame.len(), 20 + 8 + 7);
        assert_eq!(u16::from_be_bytes([frame[20 + 4], frame[20 + 5]]), 8 + 7);
    }

    #[test]
    fn oversize_datagrams_are_refused() {
        let huge = vec![0u8; 70_000];
        assert!(
            emit_udp_frame(
                std::net::Ipv4Addr::LOCALHOST,
                std::net::Ipv4Addr::LOCALHOST,
                1,
                2,
                &huge,
            )
            .is_none()
        );
    }
}
