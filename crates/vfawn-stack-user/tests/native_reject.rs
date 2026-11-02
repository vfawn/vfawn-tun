// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A rejected flow dies on the wire: the verdict becomes a real RST
//! built from the SYN's own sequence numbers (RFC 9293 §3.4), which is
//! the debt the transitional backend could not pay (it never saw the
//! SYN's bytes). The client learns the refusal in one round trip and
//! no session ever reaches the host.

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

struct Refuser {
    sessions: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for Refuser {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Reject
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
fn rejected_syn_is_answered_with_a_real_rst() {
    let handler = Arc::new(Refuser {
        sessions: AtomicUsize::new(0),
    });

    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    let script = Script::new(CLIENT, SERVER);
    device.push(&[&script.tcp(1000, 0, 0x02, b"")]);

    let mut rst = None;
    wait_for(
        || {
            let written = device.take_written();
            rst = written
                .into_iter()
                .find(|p| p.len() >= 40 && p[9] == 6 && p[33] & 0x04 == 0x04);
            rst.is_some()
        },
        "RST on the wire",
    );
    let rst = rst.expect("RST captured during the wait");

    // The RST answers the offending SYN: acknowledgment of ISN+1 (the
    // SYN consumed one octet of sequence space), sent from the server
    // the SYN aimed at (RFC 9293 §3.4, the ACK-bearing form).
    let ack = u32::from_be_bytes([rst[28], rst[29], rst[30], rst[31]]);
    assert_eq!(ack, 1001, "the RST acknowledges the SYN's sequence +1");
    assert_eq!(rst[33] & 0x14, 0x14, "RST with ACK, for a bare SYN");
    assert_eq!(
        &rst[12..16],
        &SERVER.ip().octets(),
        "the RST comes from the addressed server"
    );
    assert_eq!(&rst[16..20], &CLIENT.ip().octets());

    // The retransmitted SYN the client sends after seeing the RST is
    // swallowed: the flow is dead, and no session ever existed.
    device.push(&[&script.tcp(1000, 0, 0x02, b"")]);
    std::thread::sleep(Duration::from_millis(100));
    device.take_written();
    assert_eq!(handler.sessions.load(Ordering::SeqCst), 0);
}
