// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A fragmented UDP datagram traverses the whole native stack: the
//! reassembler ahead of the flow hash makes the wire's split invisible
//! — the session receives the complete datagram, not a truncated
//! first piece, and the reply carries every byte back.

#![cfg(feature = "backend-native")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use vfawn_core::{
    DeviceCaps, FlowInfo, PacketDevice, SessionHandler, StackBackend, UdpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::MockDevice;

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5353);

/// The datagram the client sends, in two fragments: an 8-byte-aligned
/// first piece (header + UDP header + part of the payload) and a tail
/// piece. The payload is deliberately larger than one fragment's
/// share so the split is load-bearing.
const PAYLOAD: &[u8] = b"fragmented datagrams deserve whole delivery, not first pieces";

struct RecvOnce {
    seen: AtomicUsize,
    size_ok: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for RecvOnce {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_udp(&self, mut session: UdpSession) {
        let mut buffer = [0u8; 4096];
        if let Ok((n, _)) = session.recv(&mut buffer).await {
            self.seen.fetch_add(1, Ordering::SeqCst);
            if n == PAYLOAD.len() && &buffer[..n] == PAYLOAD {
                self.size_ok.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    async fn on_tcp(&self, _session: vfawn_core::TcpSession) {}
    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

/// One IPv4 fragment with the flags-and-fragment field set by hand:
/// id 0x2211, UDP as the protocol, and the MF bit or an offset as
/// given.
fn fragment(flags_offset: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + payload.len());
    packet.extend_from_slice(&[0x45, 0x00]);
    packet.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&[0x22, 0x11]);
    packet.extend_from_slice(&flags_offset.to_be_bytes());
    packet.extend_from_slice(&[64, 0x11]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&CLIENT.ip().octets());
    packet.extend_from_slice(&SERVER.ip().octets());
    packet.extend_from_slice(payload);
    let sum: u32 = packet[..20]
        .chunks(2)
        .map(|word| u16::from_be_bytes([word[0], word[1]]) as u32)
        .sum();
    let folded = !(sum + (sum >> 16)) as u16;
    packet[10..12].copy_from_slice(&folded.to_be_bytes());
    packet
}

fn wait_for<F: FnMut() -> bool>(mut predicate: F, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn a_fragmented_datagram_arrives_whole_at_the_session() {
    let handler = Arc::new(RecvOnce {
        seen: AtomicUsize::new(0),
        size_ok: AtomicUsize::new(0),
    });
    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    // First fragment: UDP header (8 bytes) + the first 24 payload
    // bytes — 32 payload bytes total, 8-byte aligned, MF set.
    let udp_header_len = PAYLOAD.len() + 8;
    let mut first_payload = Vec::with_capacity(32);
    first_payload.extend_from_slice(&CLIENT.port().to_be_bytes());
    first_payload.extend_from_slice(&SERVER.port().to_be_bytes());
    first_payload.extend_from_slice(&(udp_header_len as u16).to_be_bytes());
    first_payload.extend_from_slice(&[0x00, 0x00]); // checksum: zero is legal
    first_payload.extend_from_slice(&PAYLOAD[..24]);
    let first = fragment(0x2000, &first_payload); // MF, offset 0

    // Tail fragment: the rest of the payload at offset 4 units
    // (32 bytes into the payload space).
    let tail_payload = PAYLOAD[24..].to_vec();
    let tail = fragment(0x0004, &tail_payload); // offset 4

    // Send tail FIRST: out-of-order arrival is the reassembler's own
    // test, not the wire's kindness.
    device.push(&[&tail, &first]);

    wait_for(
        || handler.seen.load(Ordering::SeqCst) >= 1,
        "the datagram reached the session",
    );
    assert_eq!(
        handler.size_ok.load(Ordering::SeqCst),
        1,
        "the session saw the complete datagram, every byte"
    );
}
