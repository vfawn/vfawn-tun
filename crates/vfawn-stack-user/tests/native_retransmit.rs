// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Retransmission through the production pipeline: a client that goes
//! silent gets its unacknowledged bytes again after the timeout, the
//! handshake's answer repeats while it waits, and an acknowledgment
//! stops the retries (RFC 6298 §3 and §5).

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

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

struct Echo {
    sessions: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for Echo {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 4096];
        if let Ok(n) = session.read(&mut buf).await
            && n > 0
        {
            let _ = session.write(&buf[..n]).await;
        }
        let _ = session.shutdown_write().await;
    }

    async fn on_udp(&self, _session: vfawn_core::UdpSession) {}

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

fn wait_for<F: FnMut() -> bool>(mut predicate: F, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

fn count_payload(device: &MockDevice, payload: &[u8]) -> usize {
    device
        .take_written()
        .iter()
        .filter(|p| p.len() > 40 && p[9] == 6 && &p[40..] == payload)
        .count()
}

#[test]
fn silent_client_gets_its_bytes_again_until_it_acks() {
    let handler = Arc::new(Echo {
        sessions: AtomicUsize::new(0),
    });
    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    let script = Script::new(CLIENT, SERVER);
    device.push(&[&script.tcp(1000, 0, 0x02, b"")]);
    let mut synack = None;
    wait_for(
        || {
            synack = device
                .take_written()
                .into_iter()
                .find(|p| p.len() >= 40 && p[9] == 6 && p[33] & 0x12 == 0x12);
            synack.is_some()
        },
        "SYN-ACK",
    );
    let synack = synack.expect("SYN-ACK");
    let server_seq = u32::from_be_bytes([synack[24], synack[25], synack[26], synack[27]]);
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x10, b"")]);
    let payload = b"answer me eventually";
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x18, payload)]);
    wait_for(
        || count_payload(&device, payload) >= 1,
        "the echo leaves once",
    );

    // Silence: no acknowledgment comes. The retransmission fires
    // within the first backoff window; the copies arrive seconds
    // apart, so the witness accumulates across polls.
    let mut seen_copies = 0usize;
    wait_for(
        || {
            seen_copies += count_payload(&device, payload);
            seen_copies >= 2
        },
        "the echo repeats to a silent client",
    );

    // The acknowledgment arrives; after a full further backoff window
    // the retries have stopped.
    let echo_end = 1001 + payload.len() as u32;
    device.push(&[&script.tcp(
        echo_end,
        server_seq.wrapping_add(1) + payload.len() as u32 + 1,
        0x10,
        b"",
    )]);
    std::thread::sleep(Duration::from_millis(700));
    let after = count_payload(&device, payload);
    assert_eq!(after, 0, "no further copies once acknowledged");
    let _ = seen_copies;
    assert_eq!(handler.sessions.load(Ordering::SeqCst), 1);
}

#[test]
fn the_handshakes_answer_repeats_while_it_waits() {
    let handler = Arc::new(Echo {
        sessions: AtomicUsize::new(0),
    });
    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    let script = Script::new(CLIENT, SERVER);
    device.push(&[&script.tcp(1000, 0, 0x02, b"")]);

    // The client stalls after the SYN: the SYN-ACK must come around a
    // second time with the same sequence.
    let mut first_seq = None;
    wait_for(
        || {
            for packet in device.take_written() {
                if packet.len() >= 40 && packet[9] == 6 && packet[33] & 0x12 == 0x12 {
                    let seq = u32::from_be_bytes([packet[24], packet[25], packet[26], packet[27]]);
                    match first_seq {
                        None => first_seq = Some(seq),
                        Some(seen) if seen == seq => return true,
                        _ => {}
                    }
                }
            }
            false
        },
        "a repeated SYN-ACK with the same sequence",
    );
}
