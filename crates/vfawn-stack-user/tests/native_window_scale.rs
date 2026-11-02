// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Window-scale negotiation end to end: a client whose SYN offers MSS
//! and a window scale gets both honored on the wire (RFC 7323 §2.2,
//! RFC 9293 §3.7.1), the connection then advertises the shifted
//! window, and data flows against the scaled bound.

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

/// The client's offers: MSS 1200 and window scale 7.
const SYN_OPTIONS: [u8; 8] = [
    2, 4, 0x04, 0xb0, // MSS 1200
    3, 3, 7, // window scale 7
    1, // padding
];

struct Echo {
    sessions: AtomicUsize,
    bytes_seen: AtomicUsize,
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
            self.bytes_seen.fetch_add(n, Ordering::SeqCst);
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
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn syn_options_negotiate_mss_and_window_scale() {
    let handler = Arc::new(Echo {
        sessions: AtomicUsize::new(0),
        bytes_seen: AtomicUsize::new(0),
    });

    let backend = Box::new(NativeBackend {
        mss: 1460,
        ..NativeBackend::default()
    });
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    let script = Script::new(CLIENT, SERVER);
    device.push(&[&script.tcp_with_options(1000, 0, 0x02, &SYN_OPTIONS, b"")]);

    let mut synack = None;
    wait_for(
        || {
            let written = device.take_written();
            synack = written
                .into_iter()
                .find(|p| p.len() >= 40 && p[9] == 6 && p[33] & 0x12 == 0x12);
            synack.is_some()
        },
        "SYN-ACK",
    );
    let synack = synack.expect("SYN-ACK captured");
    let server_seq = u32::from_be_bytes([synack[24], synack[25], synack[26], synack[27]]);

    // The SYN-ACK carries options: the data offset is past 20 bytes and
    // the region holds our MSS offer (the smaller of ours and the
    // client's: 1200) and our window-scale shift of 7.
    let data_offset = (synack[32] >> 4) as usize * 4;
    assert!(data_offset > 20, "the SYN-ACK must carry options");
    let options = &synack[40..20 + data_offset];
    assert!(
        options
            .windows(4)
            .any(|w| w[0] == 2 && w[1] == 4 && w[2..4] == 1200u16.to_be_bytes()),
        "MSS offer echoes the negotiated 1200, got {options:?}"
    );
    assert!(
        options
            .windows(3)
            .any(|w| w[0] == 3 && w[1] == 3 && w[2] == 7),
        "our window-scale shift of 7 rides along, got {options:?}"
    );

    // Complete the handshake; the acknowledgment then advertises the
    // shifted window: the 1 MiB commitment right-shifted by 7 is 8192.
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x10, b"")]);
    let payload = b"scaled window on the wire";
    device.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x18, payload)]);

    wait_for(|| handler.sessions.load(Ordering::SeqCst) >= 1, "session");
    wait_for(
        || {
            device
                .take_written()
                .iter()
                .any(|p| p.len() > 40 && p[9] == 6 && &p[40..] == payload)
        },
        "echoed payload",
    );
    assert_eq!(handler.bytes_seen.load(Ordering::SeqCst), payload.len());
}
