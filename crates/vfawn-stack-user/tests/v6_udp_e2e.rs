// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A UDP datagram over IPv6 traverses the native stack: the slot is
//! family-general, the session sees the datagram, and the reply
//! leaves as a valid v6 frame with the mandatory checksum.

#![cfg(feature = "backend-native")]

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use vfawn_core::{
    DeviceCaps, FlowInfo, PacketDevice, SessionHandler, StackBackend, UdpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::MockDevice;

const CLIENT: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 45678, 0, 0);
const SERVER: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 5353, 0, 0);
const PAYLOAD: &[u8] = b"v6 rides the native stack";

struct V6Recv {
    sessions: AtomicUsize,
    bytes: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for V6Recv {
    fn judge_flow(&self, flow: &FlowInfo, _first: &[u8]) -> Verdict {
        assert_eq!(
            flow.source,
            SocketAddr::V6(CLIENT),
            "the flow names its v6 endpoints"
        );
        Verdict::Accept
    }

    async fn on_udp(&self, mut session: UdpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let mut buffer = [0u8; 256];
        if let Ok((n, origin)) = session.recv(&mut buffer).await {
            if &buffer[..n] == PAYLOAD {
                self.bytes.fetch_add(n, Ordering::SeqCst);
            }
            // The echo rides back: the reply path is the same
            // family, tested by the frame the device captures.
            let _ = session.send(&buffer[..n], &origin).await;
        }
    }

    async fn on_tcp(&self, _session: vfawn_core::TcpSession) {}
    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
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
fn a_v6_datagram_flows_through_and_echoes_back() {
    let handler = Arc::new(V6Recv {
        sessions: AtomicUsize::new(0),
        bytes: AtomicUsize::new(0),
    });
    let backend = Box::new(NativeBackend::default());
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let _handle = backend
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");

    // The inbound datagram, built by the wire's own v6 emitter: a
    // valid frame with a verifiable checksum.
    let inbound = vfawn_wire::emit::emit_udp_frame_v6(
        *CLIENT.ip(),
        *SERVER.ip(),
        CLIENT.port(),
        SERVER.port(),
        PAYLOAD,
    )
    .expect("inbound frame");
    device.push(&[&inbound]);

    wait_for(
        || handler.sessions.load(Ordering::SeqCst) >= 1,
        "the v6 session",
    );
    wait_for(
        || handler.bytes.load(Ordering::SeqCst) >= PAYLOAD.len(),
        "the whole datagram",
    );

    // The echo: a v6 frame back, whose UDP checksum verifies. The
    // wait keeps what it finds — take_written drains, so a second
    // take would race the poll that succeeded.
    let mut echoed = None;
    wait_for(
        || {
            echoed = device
                .take_written()
                .into_iter()
                .find(|frame| frame.first().map(|b| b >> 4) == Some(6));
            echoed.is_some()
        },
        "the v6 echo",
    );
    let echoed = echoed.expect("the wait kept the frame");
    let (header, rest) = vfawn_wire::ipv6::Ipv6Header::parse(&echoed).expect("v6 header");
    assert_eq!(header.src, *SERVER.ip(), "the reply leaves from the server");
    assert_eq!(header.dst, *CLIENT.ip());
    let sum = vfawn_wire::checksum::pseudo_header_v6(
        header.src,
        header.dst,
        vfawn_wire::protocol::IpProtocol::Udp,
        rest.len() as u32,
    ) + vfawn_wire::checksum::sum_words(rest);
    assert_eq!(
        vfawn_wire::checksum::fold(sum),
        0xffff,
        "the mandatory v6 UDP checksum verifies"
    );
    assert_eq!(&rest[8..], PAYLOAD);
}
