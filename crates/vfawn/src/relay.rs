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

use bytes::BytesMut;
// The protect callback takes the platform's own socket descriptor: a
// file descriptor on Unix, a socket handle on Windows. The hook's
// contract is the platform's notion of "the socket", not ours.
#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(windows)]
use std::os::windows::io::RawSocket as RawFd;
use std::sync::Arc;
use vfawn_core::{FlowInfo, IcmpPacket, Network, SessionHandler, TcpSession, UdpSession, Verdict};

/// Protects an outbound socket from being captured back into the
/// device that spawned its session.
pub type Protect = Arc<dyn Fn(RawFd) -> io::Result<()> + Send + Sync>;

/// The dial-time socket as the protect hook sees it, by the platform's
/// own descriptor notion.
#[cfg(unix)]
fn raw_descriptor_of(socket: &socket2::Socket) -> RawFd {
    use std::os::fd::AsRawFd;
    socket.as_raw_fd()
}

#[cfg(windows)]
fn raw_descriptor_of(socket: &socket2::Socket) -> RawFd {
    use std::os::windows::io::AsRawSocket;
    socket.as_raw_socket()
}

/// The UDP session's socket under the same contract.
#[cfg(unix)]
fn udp_raw_descriptor(socket: &tokio::net::UdpSocket) -> RawFd {
    use std::os::fd::AsRawFd;
    socket.as_raw_fd()
}

#[cfg(windows)]
fn udp_raw_descriptor(socket: &tokio::net::UdpSocket) -> RawFd {
    use std::os::windows::io::AsRawSocket;
    socket.as_raw_socket()
}

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
        protect(raw_descriptor_of(&socket))?;
    }
    // The blocking connect off the async workers: the socket keeps the
    // device binding across it, and the result returns to async land.
    let connected = tokio::task::spawn_blocking(move || -> io::Result<std::net::TcpStream> {
        let address = socket2::SockAddr::from(destination);
        socket.connect(&address)?;
        socket.set_nodelay(true)?;
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
        use tokio::io::AsyncWriteExt;
        // Every line this session writes names its flow, so the log
        // reads as a session list rather than anonymous exits.
        let source = session.flow().source;
        let destination = session.flow().destination;
        let mut outbound = match dial_tcp(&self.protect, destination).await {
            Ok(stream) => stream,
            Err(error) => {
                // The flow is live on the client side and dead on the
                // origin side; saying nothing here strands the client
                // waiting for an answer that will never come. The
                // line names the dial's refusal in the log; the
                // session's drop closes the event channel, which is
                // the slot's signal to reset the flow.
                eprintln!("vfawn: relay tcp {source} -> {destination} dial failed ({error})");
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
            use std::os::fd::AsRawFd;
            let flow = session.flow();
            if let Some(key) = relay_flow_key(flow) {
                let fd = outbound.as_raw_fd();
                vfawn_stack_user::splice_lane::SpliceLane::global().register(key, fd);
            }
        }

        // Both directions park holding nothing: the client side waits
        // on the session's channel (the bytes it carries ARE the
        // buffer), and the origin side waits on readiness alone — the
        // read's storage lives only inside the arm that uses it. A
        // parked relay therefore costs no buffers, which was half of
        // the measured eight-kilobyte session. The allocator is the
        // pool: a burst allocates, the write's completion frees, and
        // an idle session owns neither.
        loop {
            tokio::select! {
                from_client = session.read_owned() => match from_client {
                    Ok(bytes) if bytes.is_empty() => {
                        eprintln!("vfawn: relay tcp {source} -> {destination} exit: client EOF");
                        break;
                    }
                    Err(error) => {
                        eprintln!("vfawn: relay tcp {source} -> {destination} exit: client read error {error}");
                        break;
                    }
                    Ok(bytes) => {
                        if let Err(error) = outbound.write_all(&bytes).await {
                            eprintln!("vfawn: relay tcp {source} -> {destination} exit: outbound write {error}");
                            break;
                        }
                    }
                },
                ready = outbound.readable() => match ready {
                    Err(error) => {
                        eprintln!("vfawn: relay tcp {source} -> {destination} exit: origin readable {error}");
                        break;
                    }
                    Ok(()) => {
                        // Downlink rides the session's write lane into
                        // the slot's drain. The relay-side frame builder
                        // this arm once carried was parked on evidence
                        // twice over: its local sequence cursor desynced
                        // from the connection's (the client saw out-of-
                        // order frames), and re-pointing it at the TUN
                        // channel made the channel multi-producer, which
                        // collapsed both directions. The drain owns
                        // downlink; this side only moves bytes.
                        // One readiness, one large read: the socket
                        // usually holds far more than a segment's worth
                        // (the sender's bursts land whole), and every
                        // extra byte here is a hop through the write
                        // lane, the shard, and the writer that the
                        // next read would otherwise pay again.
                        let mut down = BytesMut::with_capacity(65536);
                        match outbound.try_read_buf(&mut down) {
                            // A readiness race, not an error: the socket
                            // said readable, the read found nothing, and
                            // the answer is to wait again — treating it
                            // as an exit killed every relay at its first
                            // spurious wake.
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                continue;
                            }
                            Ok(0) => {
                                eprintln!("vfawn: relay tcp {source} -> {destination} exit: origin EOF");
                                break;
                            }
                            Err(error) => {
                                eprintln!("vfawn: relay tcp {source} -> {destination} exit: origin read {error}");
                                break;
                            }
                            Ok(_) => {
                                if let Err(error) = session.write(&down).await {
                                    eprintln!("vfawn: relay tcp {source} -> {destination} exit: session write {error}");
                                    break;
                                }
                            }
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
        let source = session.flow().source;
        let peer = session.flow().destination;
        let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
            return;
        };
        if let Some(protect) = &self.protect
            && protect(udp_raw_descriptor(&socket)).is_err()
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
                        if session.send(&from_origin[..n], &source).await.is_err() {
                            break;
                        }
                    }
                },
            }
        }
        eprintln!("vfawn: relay udp {source} -> {peer} exit");
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
