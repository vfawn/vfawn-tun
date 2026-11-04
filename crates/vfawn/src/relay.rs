// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A direct relay: each captured session dials its own original
//! destination and copies bytes both ways.
//!
//! This is the handler a benchmark wants, because traffic traverses
//! the whole pipeline (device, stack, session) and leaves through a
//! real socket, the same seat a proxy kernel occupies. It is also the
//! smallest useful host integration: nothing here knows any proxy
//! protocol, it just exercises the session contract end to end.
//!
//! Outbound sockets must escape the capture that feeds them; the host
//! supplies a protect callback (bind-to-device on Linux, the VPN
//! service on Android) and every dial passes through it.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use vfawn_core::{FlowInfo, IcmpPacket, Network, SessionHandler, TcpSession, UdpSession, Verdict};

/// Protects an outbound socket from being captured back into the
/// device that spawned its session.
pub type Protect = Arc<dyn Fn(RawFd) -> io::Result<()> + Send + Sync>;

async fn dial_tcp(
    protect: &Option<Protect>,
    destination: std::net::SocketAddr,
) -> io::Result<tokio::net::TcpStream> {
    let domain = if destination.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if let Some(protect) = protect {
        protect(socket.as_raw_fd())?;
    }
    // The blocking connect off the async workers: the socket keeps the
    // device binding across it, and the result returns to async land.
    let connected = tokio::task::spawn_blocking(move || -> io::Result<std::net::TcpStream> {
        let address = socket2::SockAddr::from(destination);
        socket.connect(&address)?;
        socket.set_nonblocking(true)?;
        Ok(std::net::TcpStream::from(socket))
    })
    .await
    .map_err(|e| io::Error::other(e.to_string()))??;
    tokio::net::TcpStream::from_std(connected)
}

/// A session handler that connects to whatever destination each flow
/// carried and relays bytes.
pub struct RelayHandler {
    protect: Option<Protect>,
}

impl RelayHandler {
    /// A relay whose dials go through `protect`; `None` dials plainly,
    /// which is right only when nothing captures the host's traffic.
    pub fn new(protect: Option<Protect>) -> Self {
        Self { protect }
    }
}

#[async_trait::async_trait]
impl SessionHandler for RelayHandler {
    fn judge_flow(&self, flow: &FlowInfo, _first_packet: &[u8]) -> Verdict {
        match flow.network {
            Network::Tcp | Network::Udp => Verdict::Accept,
            // Passing ICMP through unchanged needs kernel rewrites the
            // relay does not carry; the datagram dies here.
            Network::Icmp => Verdict::Drop,
            _ => Verdict::Drop,
        }
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let destination = session.flow().destination;
        let mut outbound = match dial_tcp(&self.protect, destination).await {
            Ok(stream) => stream,
            Err(_) => {
                return;
            }
        };
        // The fast path's registration: the outbound socket's fd goes
        // into the splice lane under the flow's key, so the shard can
        // send payload bytes straight to it without the session
        // channel's hop. The registration lives as long as the
        // connection (removed on return from this function).
        #[cfg(all(feature = "backend-native", target_os = "linux"))]
        {
            let flow = session.flow();
            if let Some(key) = relay_flow_key(flow) {
                let fd = outbound.as_raw_fd();
                vfawn_stack_user::splice_lane::SpliceLane::global().register(key, fd);
            }
        }
        // The downlink fast path's context: the flow's addresses and
        // the lane, captured for the read loop below.
        #[cfg(all(feature = "backend-native", target_os = "linux"))]
        let fast_down = relay_flow_key(session.flow()).map(|key| {
            let flow = session.flow();
            (
                key,
                vfawn_stack_user::splice_lane::SpliceLane::global(),
                flow,
            )
        });

        let mut up = [0u8; 16384];
        let mut down = [0u8; 16384];
        // The fast path's send-sequence cursor: starts at the
        // connection's established sequence (the relay's first byte
        // rides at the handshake's next sequence number, which the
        // fast path tracks locally; the slow path's cursor stays in
        // the shard slot, and the two converge because every byte
        // passes through exactly one of them).
        #[cfg(all(feature = "backend-native", target_os = "linux"))]
        let mut next_send_seq: u32 = 1;
        #[cfg(all(feature = "backend-native", target_os = "linux"))]
        let mut flow_ack: u32 = 1;
        loop {
            tokio::select! {
                from_client = session.read(&mut up) => match from_client {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        #[cfg(all(feature = "backend-native", target_os = "linux"))]
                        {
                            // The client's data advances the ack we
                            // stamp on downlink frames.
                            flow_ack = flow_ack.wrapping_add(n as u32);
                        }
                        if outbound.write_all(&up[..n]).await.is_err() {
                            break;
                        }
                    }
                },
                from_origin = outbound.read(&mut down) => match from_origin {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        // The downlink fast path: build the frames here
                        // and push straight to the TUN, skipping the
                        // session's write lane and the shard's drain.
                        // Falls back to the session when the lane is
                        // absent or the device is gone.
                        #[cfg(all(feature = "backend-native", target_os = "linux"))]
                        {
                            if let Some((_, lane, flow)) = &fast_down {
                                let (src_v4, dst_v4) = match (
                                    flow.destination.ip(),
                                    flow.source.ip(),
                                ) {
                                    (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
                                        (a, b)
                                    }
                                    _ => break,
                                };
                                // The fast downlink now lives inside the
                                // slot's drain: session.write lands in the
                                // lane, and the registered flow's drain
                                // pushes frames straight to the TUN channel
                                // (same sequence cursor, same window
                                // arithmetic, zero coordination). This arm
                                // just writes; the slot does the rest.
                                if false {
                                let _ = vfawn_stack_user::fast_down::push_downlink(
                                    &vfawn_stack_user::fast_down::DownlinkContext {
                                        lane,
                                        src: std::net::SocketAddrV4::new(src_v4, flow.destination.port()),
                                        dst: std::net::SocketAddrV4::new(dst_v4, flow.source.port()),
                                        seq: next_send_seq,
                                        ack: flow_ack,
                                        window: 65535,
                                        mss: 1460,
                                    },
                                    &down[..n],
                                );
                                if pushed {
                                    continue;
                                }
                                }
                            }
                        }
                        if session.write(&down[..n]).await.is_err() {
                            break;
                        }
                    }
                },
            }
        }
        let _ = session.shutdown_write().await;
        #[cfg(all(feature = "backend-native", target_os = "linux"))]
        {
            let flow = session.flow();
            if let Some(key) = relay_flow_key(flow) {
                vfawn_stack_user::splice_lane::SpliceLane::global().unregister(&key);
            }
        }
    }

    async fn on_udp(&self, mut session: UdpSession) {
        let peer = session.flow().destination;
        let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
            return;
        };
        if let Some(protect) = &self.protect
            && protect(socket.as_raw_fd()).is_err()
        {
            return;
        }
        // Deliberately not connected: the origin may answer from any of
        // its addresses (the kernel picks one by route), and a connected
        // socket would drop exactly those replies as source mismatches.
        let _ = peer;
        let mut from_client = [0u8; 1500];
        let mut from_origin = [0u8; 1500];
        loop {
            tokio::select! {
                received = session.recv(&mut from_client) => match received {
                    Err(_) => break,
                    Ok((0, _)) => {}
                    Ok((n, _)) => {
                        if socket.send_to(&from_client[..n], peer).await.is_err() {
                            break;
                        }
                    }
                },
                answered = socket.recv_from(&mut from_origin) => match answered {
                    Err(_) => break,
                    Ok((0, _)) => {}
                    Ok((n, _)) => {
                        let client = session.flow().source;
                        if session.send(&from_origin[..n], &client).await.is_err() {
                            break;
                        }
                    }
                },
            }
        }
    }

    async fn on_icmp(&self, _packet: IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

/// Derive the shard's dispatch key from the session's flow info.
/// The key is the five-tuple the wire layer parses out of packets;
/// the session's FlowInfo carries the same addresses in its source
/// and destination.
#[cfg(all(feature = "backend-native", target_os = "linux"))]
fn relay_flow_key(flow: &vfawn_core::FlowInfo) -> Option<vfawn_wire::flow::FlowKey> {
    use std::net::IpAddr;
    let (src, dst) = match (flow.source.ip(), flow.destination.ip()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (a, b),
        _ => return None,
    };
    Some(vfawn_wire::flow::FlowKey {
        src: IpAddr::V4(src),
        src_port: flow.source.port(),
        dst: IpAddr::V4(dst),
        dst_port: flow.destination.port(),
        protocol: vfawn_wire::protocol::IpProtocol::Tcp,
    })
}
