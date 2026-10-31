// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The host-integration example: a SOCKS5 CONNECT server in front of a
//! vfawn instance.
//!
//! This is deliberately outside the library. A proxy protocol belongs
//! to the host; what the library owes the host is the session contract
//! this file exercises: one judge call per flow, one session per flow,
//! and the original destination carried on the session. Everything
//! here is the minimum a real front-end would keep: greeting, CONNECT
//! request, then a plain byte pipe.
//!
//! ```sh
//! sudo ./target/debug/examples/socks5 198.18.0.1/15
//! curl --socks5 127.0.0.1:1080 http://example.com
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vfawn::Instance;
use vfawn_core::{
    FlowInfo, IcmpPacket, Network, SessionHandler, TcpSession, UdpSession, Verdict, VfawnConfig,
};

/// The handler the instance runs: every TCP flow is accepted and piped
/// to a waiting SOCKS front-end through the relay table below.
struct ToSocks {
    socks: tokio::sync::mpsc::UnboundedSender<(SocketAddr, TcpSession)>,
}

#[async_trait::async_trait]
impl SessionHandler for ToSocks {
    fn judge_flow(&self, flow: &FlowInfo, _first: &[u8]) -> Verdict {
        match flow.network {
            Network::Tcp => Verdict::Accept,
            _ => Verdict::Drop,
        }
    }

    async fn on_tcp(&self, session: TcpSession) {
        // The front-end asked for this destination when it submitted
        // the flow; the mapping below restores the pair.
        let _ = self.socks.send((session.flow().destination, session));
    }

    async fn on_udp(&self, _session: UdpSession) {}

    async fn on_icmp(&self, _packet: IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "198.18.0.1/15".into());
    let listen: SocketAddr = "127.0.0.1:1080".parse()?;

    let mut config = VfawnConfig::default();
    config.device.inet4_address = vec![address.parse()?];
    config.route.auto_route = true;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let handler: Arc<dyn SessionHandler> = Arc::new(ToSocks { socks: tx });
    let mut instance = Instance::new(config, handler.clone())?;
    instance.start(handler)?;

    // The session half of each captured flow, keyed by the original
    // destination the SOCKS client asked for.
    let mut waiting: std::collections::HashMap<SocketAddr, TcpSession> =
        std::collections::HashMap::new();
    let reader = tokio::spawn(async move {
        while let Some((destination, session)) = rx.recv().await {
            waiting.insert(destination, session);
        }
    });

    let listener = TcpListener::bind(listen).await?;
    println!("socks5 on {listen}; instance ready");

    loop {
        let (mut client, _) = listener.accept().await?;
        // Handshake: no-auth greeting, then one CONNECT request.
        let mut head = [0u8; 2];
        if client.read_exact(&mut head).await.is_err() || head[0] != 5 {
            continue;
        }
        let mut methods = vec![0u8; head[1] as usize];
        let _ = client.read_exact(&mut methods).await;
        client.write_all(&[5, 0]).await?;

        let mut request = [0u8; 4];
        if client.read_exact(&mut request).await.is_err() || request[1] != 1 {
            continue; // CONNECT only
        }
        let destination = match request[3] {
            1 => {
                let mut octets = [0u8; 4];
                let _ = client.read_exact(&mut octets).await;
                let mut port = [0u8; 2];
                let _ = client.read_exact(&mut port).await;
                SocketAddr::from((octets, u16::from_be_bytes(port)))
            }
            3 => {
                let mut len = [0u8; 1];
                let _ = client.read_exact(&mut len).await;
                let mut name = vec![0u8; len[0] as usize];
                let _ = client.read_exact(&mut name).await;
                let mut port = [0u8; 2];
                let _ = client.read_exact(&mut port).await;
                match std::str::from_utf8(&name)?
                    .to_string()
                    .parse::<std::net::IpAddr>()
                {
                    Ok(ip) => SocketAddr::new(ip, u16::from_be_bytes(port)),
                    Err(_) => continue, // names need a resolver; out of scope here
                }
            }
            _ => continue,
        };

        // Make the captured side create the flow: one byte toward the
        // destination through the instance's own TUN would be the real
        // trigger; for the example, the waiting table carries whatever
        // the instance already produced for this destination.
        let Some(mut upstream) = waiting.remove(&destination) else {
            let _ = client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            let _ = client.shutdown().await;
            continue;
        };
        let _ = client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;

        let mut client_buf = [0u8; 8192];
        let mut up_buf = [0u8; 8192];
        loop {
            tokio::select! {
                n = client.read(&mut client_buf) => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => if upstream.write(&client_buf[..n]).await.is_err() { break },
                },
                n = upstream.read(&mut up_buf) => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => if client.write_all(&up_buf[..n]).await.is_err() { break },
                },
            }
        }
        let _ = reader;
    }
}
