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

        let mut up = [0u8; 16384];
        let mut down = [0u8; 16384];
        loop {
            tokio::select! {
                from_client = session.read(&mut up) => match from_client {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if outbound.write_all(&up[..n]).await.is_err() {
                            break;
                        }
                    }
                },
                from_origin = outbound.read(&mut down) => match from_origin {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if session.write(&down[..n]).await.is_err() {
                            break;
                        }
                    }
                },
            }
        }
        let _ = session.shutdown_write().await;
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
