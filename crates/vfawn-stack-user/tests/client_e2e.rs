// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The active-open engine against a scripted peer.
//!
//! The client stack sends its SYN, a handcrafted SYN-ACK completes the
//! handshake, and data crosses both ways. This pins the half the passive
//! backend cannot: the SYN-SENT state, the response's sequence checks,
//! and the host session delivered after the handshake.

#![cfg(feature = "backend-native")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use vfawn_core::{DeviceCaps, PacketDevice};
use vfawn_stack_user::native_tcp::{Reaction, ctl, emit_tcp};
use vfawn_stack_user::{ClientConfig, ClientStack};
use vfawn_testsuite::MockDevice;
use vfawn_wire::tcp::TcpHeader;

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const REMOTE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);

fn tcp_of(packet: &[u8]) -> Option<(TcpHeader, &[u8])> {
    if packet.first()? >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet.first()? & 0x0f) * 4;
    let (header, payload) = TcpHeader::parse(packet.get(ihl..)?).ok()?;
    Some((header, payload))
}

fn wait_for<F>(device: &MockDevice, mut matches: F, timeout: Duration) -> Option<Vec<u8>>
where
    F: FnMut(&[u8]) -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        for packet in device.take_written() {
            if matches(&packet) {
                return Some(packet);
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_open_handshake_and_data() -> Result<(), Box<dyn std::error::Error>> {
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let reader = device.duplicate()?;
    let stack = ClientStack::start(reader, ClientConfig::new(IpAddr::V4(LOCAL)))?;

    let connecting = tokio::spawn({
        let stack = stack.clone();
        async move { stack.connect(REMOTE).await }
    });

    let syn = wait_for(
        &device,
        |packet| tcp_of(packet).is_some_and(|(header, _)| header.flags.bits() & ctl::SYN != 0),
        Duration::from_secs(2),
    )
    .ok_or("no SYN")?;
    let (syn_header, _) = tcp_of(&syn).ok_or("bad SYN")?;
    let local = SocketAddr::new(IpAddr::V4(LOCAL), syn_header.src_port);
    let client_isn = syn_header.seq;

    let server_isn = 0x1122_3344;
    let synack = emit_tcp(
        REMOTE,
        local,
        &Reaction::segment(
            server_isn,
            client_isn.wrapping_add(1),
            ctl::SYN | ctl::ACK,
            65535,
        ),
        &[],
        &[],
    );
    device.push(&[&synack]);

    let mut stream = connecting.await??;

    let hello = emit_tcp(
        REMOTE,
        local,
        &Reaction::segment(
            server_isn.wrapping_add(1),
            client_isn.wrapping_add(1),
            ctl::ACK,
            65535,
        ),
        &[],
        b"hello",
    );
    device.push(&[&hello]);

    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer)).await??;
    assert_eq!(&buffer[..read], b"hello");

    stream.write(b"world").await?;
    let out = wait_for(
        &device,
        |packet| {
            tcp_of(packet).is_some_and(|(header, payload)| {
                header.ack == server_isn.wrapping_add(6) && payload == b"world"
            })
        },
        Duration::from_secs(2),
    );
    assert!(out.is_some(), "the client's data never reached the wire");

    Ok(())
}
