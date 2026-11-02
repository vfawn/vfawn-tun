// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Handshake-load shape: many clients connecting at once, the way a
//! session-memory bench does. The bar is every handshake completing
//! stack-side (the host sees every flow), not just client-side.

#![cfg(feature = "backend-native")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vfawn_core::{
    DeviceCaps, FlowInfo, PacketDevice, SessionHandler, StackBackend, TcpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::{MockDevice, Script};

const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);
const CLIENTS: usize = 2000;

struct Count {
    sessions: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for Count {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_tcp(&self, _session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
    }

    async fn on_udp(&self, _session: vfawn_core::UdpSession) {}

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

fn wait_for<F: FnMut() -> bool>(mut predicate: F, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

fn dst_port_of(packet: &[u8]) -> Option<u16> {
    if packet.len() < 24 || packet[9] != 6 {
        return None;
    }
    Some(u16::from_be_bytes([packet[22], packet[23]]))
}

#[test]
fn two_thousand_concurrent_handshakes_all_reach_the_host() {
    let handler = Arc::new(Count {
        sessions: AtomicUsize::new(0),
    });

    let backend = Box::new(NativeBackend {
        mss: 1460,
        ..NativeBackend::default()
    });
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    // All the SYNs at once, then collect the SYN-ACKs, then all the
    // completing ACKs: the same packet pattern the memory bench's
    // 400-concurrent client produces, only tighter.
    let scripts: Vec<Script> = (0..CLIENTS)
        .map(|index| {
            let client = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 30000 + index as u16);
            Script::new(client, SERVER)
        })
        .collect();

    let mut syns: Vec<Vec<u8>> = Vec::with_capacity(CLIENTS);
    for script in &scripts {
        syns.push(script.tcp(1000, 0, 0x02, b""));
    }
    let refs: Vec<&[u8]> = syns.iter().map(|p| p.as_slice()).collect();
    device.push(&refs);

    let mut server_seqs: Vec<(u16, u32)> = Vec::new();
    wait_for(
        || {
            for packet in device.take_written() {
                if packet.len() >= 40
                    && packet[9] == 6
                    && packet[33] & 0x12 == 0x12
                    && let Some(port) = dst_port_of(&packet)
                    && !server_seqs.iter().any(|(p, _)| *p == port)
                {
                    let seq = u32::from_be_bytes([packet[24], packet[25], packet[26], packet[27]]);
                    server_seqs.push((port, seq));
                }
            }
            server_seqs.len() >= CLIENTS
        },
        "every SYN answered",
    );

    // Each completing ACK names its flow's cookie ISN; pair the
    // scripts with their SYN-ACKs by client port.
    let mut by_port: Vec<(u16, u32)> = server_seqs;
    by_port.sort_by_key(|(p, _)| *p);
    let mut acks: Vec<Vec<u8>> = Vec::with_capacity(CLIENTS);
    for (index, script) in scripts.iter().enumerate() {
        let port = 30000 + index as u16;
        let seq = by_port
            .iter()
            .find(|(p, _)| *p == port)
            .map(|(_, s)| *s)
            .expect("seq for port");
        acks.push(script.tcp(1001, seq.wrapping_add(1), 0x10, b""));
    }
    let refs: Vec<&[u8]> = acks.iter().map(|p| p.as_slice()).collect();
    device.push(&refs);

    wait_for(
        || handler.sessions.load(Ordering::SeqCst) >= CLIENTS,
        "every handshake reaches the host",
    );

    assert_eq!(
        handler.sessions.load(Ordering::SeqCst),
        CLIENTS,
        "every completing ACK must establish its slot"
    );
}
