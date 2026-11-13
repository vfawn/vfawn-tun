// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A stopping ipstack backend resets the connections it still holds,
//! and the resets reach the device before it closes, as the native
//! stack's do (`native_stop_reset.rs`): sing-tun's gVisor stack aborts
//! every endpoint on close and closes the tun after
//! (`stack_gvisor.go:131-135`), and a connected endpoint's abort sends
//! `<SEQ=SND.NXT><ACK=RCV.NXT><RST,ACK>` (gVisor `connect.go:1069-1088`).
//! ipstack 1.0 has no abort and drops its streams silently, so the
//! bridge builds the resets from the cursors it saw on the wire. Without
//! them, a client holding the connection reads on until its own timeout.

#![cfg(feature = "backend-ipstack")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vfawn_core::{
    Action, DeviceCaps, FlowInfo, IcmpPacket, PacketDevice, SessionHandler, StackBackend,
    TcpSession, UdpSession, Verdict,
};
use vfawn_stack_user::IpstackBackend;
use vfawn_testsuite::{MockDevice, Script};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const HALF_OPEN: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45679);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

const GREETING: &[u8] = b"hello";

/// Answers the client's first bytes with a greeting, then holds the
/// connection open reading until it ends: the relay a client keeps a
/// connection through. Reading first keeps the greeting behind the
/// handshake: ipstack lets a stream's first write out ahead of its own
/// SYN-ACK, before the ISN, where the client discards it.
struct GreetAndHold {
    sessions: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for GreetAndHold {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 4096];
        if !matches!(session.read(&mut buf).await, Ok(n) if n > 0) {
            return;
        }
        let _ = session.write(GREETING).await;
        while let Ok(n) = session.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    }

    async fn on_udp(&self, _session: UdpSession) {}

    async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
        Action::Drop
    }
}

/// A TCP segment the stack wrote: the client port it is bound for, its
/// flags, cursors and payload (IPv4 without options).
struct Segment {
    client_port: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    payload: Vec<u8>,
}

fn segment(packet: &[u8]) -> Option<Segment> {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]])).min(packet.len());
    let tcp = packet.get(ihl..total)?;
    let data_offset = usize::from(tcp.get(12)? >> 4) * 4;
    Some(Segment {
        client_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        flags: tcp[13],
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        payload: tcp.get(data_offset..)?.to_vec(),
    })
}

/// Drain the device's sink until `pick` finds a segment, keeping
/// everything seen.
fn wait_for_segment(
    device: &MockDevice,
    seen: &mut Vec<Segment>,
    what: &str,
    pick: impl Fn(&Segment) -> bool,
) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        seen.extend(device.take_written().iter().filter_map(|p| segment(p)));
        if let Some(index) = seen.iter().position(&pick) {
            return index;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn a_stop_resets_live_connections_before_the_device_closes() {
    let handler = Arc::new(GreetAndHold {
        sessions: AtomicUsize::new(0),
    });
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = Box::new(IpstackBackend::default())
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn ipstack backend");
    let mut seen = Vec::new();

    // One connection established, with bytes both ways.
    let client = Script::new(CLIENT, SERVER);
    device.push(&[&client.tcp(1000, 0, 0x02, b"")]);
    let synack = wait_for_segment(&device, &mut seen, "SYN-ACK", |s| {
        s.client_port == CLIENT.port() && s.flags & 0x12 == 0x12
    });
    let server_isn = seen[synack].seq;
    let request = b"ping";
    device.push(&[&client.tcp(1001, server_isn.wrapping_add(1), 0x10, b"")]);
    device.push(&[&client.tcp(1001, server_isn.wrapping_add(1), 0x18, request)]);
    // SND.NXT past the SYN and the greeting; RCV.NXT past the request.
    let send_nxt = server_isn
        .wrapping_add(1)
        .wrapping_add(GREETING.len() as u32);
    let recv_nxt = 1001 + request.len() as u32;
    wait_for_segment(&device, &mut seen, "the greeting", |s| {
        s.client_port == CLIENT.port() && s.payload == GREETING
    });
    wait_for_segment(&device, &mut seen, "the request's acknowledgment", |s| {
        s.client_port == CLIENT.port() && s.ack == recv_nxt
    });
    assert_eq!(handler.sessions.load(Ordering::SeqCst), 1);

    // A second flow left in SYN-RECEIVED: gVisor closes it unannounced.
    let half_open = Script::new(HALF_OPEN, SERVER);
    device.push(&[&half_open.tcp(5000, 0, 0x02, b"")]);
    wait_for_segment(&device, &mut seen, "the half-open SYN-ACK", |s| {
        s.client_port == HALF_OPEN.port() && s.flags & 0x12 == 0x12
    });
    seen.clear();

    handle.stop();

    // The device closes once the bridge is done with it; a closed mock
    // refuses every write, so whatever its sink holds was written
    // before the close.
    let mut probe = device.duplicate().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while probe.write_batch(&mut []).is_ok() {
        assert!(
            Instant::now() < deadline,
            "the stop never closed the device"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    seen.extend(device.take_written().iter().filter_map(|p| segment(p)));

    let resets: Vec<&Segment> = seen.iter().filter(|s| s.flags & 0x04 != 0).collect();
    assert_eq!(
        resets.len(),
        1,
        "exactly the established connection is reset before the close"
    );
    let reset = resets[0];
    assert_eq!(reset.client_port, CLIENT.port());
    assert_eq!(reset.flags, 0x14, "RST|ACK");
    assert_eq!(reset.seq, send_nxt, "the reset carries SND.NXT");
    assert_eq!(reset.ack, recv_nxt, "the reset acknowledges RCV.NXT");

    // The sessions still end: the handler's read fails and it returns.
    assert!(
        matches!(
            handle.drain(Duration::from_secs(5)),
            vfawn_core::Drain::Idle
        ),
        "the held session finished within the drain window"
    );
}

/// A connection the handler finished with is not reset: its stream is
/// gone, and ipstack owes the client nothing more for it.
#[test]
fn a_finished_session_is_not_reset() {
    /// Reads one segment's bytes, then lets the session go.
    struct ReadsOnce;

    #[async_trait::async_trait]
    impl SessionHandler for ReadsOnce {
        fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
            Verdict::Accept
        }
        async fn on_tcp(&self, mut session: TcpSession) {
            let mut buf = [0u8; 64];
            let _ = session.read(&mut buf).await;
        }
        async fn on_udp(&self, _session: UdpSession) {}
        async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
            Action::Drop
        }
    }

    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let handle = Box::new(IpstackBackend::default())
        .spawn(device.duplicate().unwrap(), Arc::new(ReadsOnce))
        .expect("spawn ipstack backend");
    let mut seen = Vec::new();
    let client = Script::new(CLIENT, SERVER);
    device.push(&[&client.tcp(1000, 0, 0x02, b"")]);
    let synack = wait_for_segment(&device, &mut seen, "SYN-ACK", |s| s.flags & 0x12 == 0x12);
    let server_isn = seen[synack].seq;
    // Established before the handler lets go, so no segment of the
    // client's reaches ipstack after the stream is gone.
    device.push(&[&client.tcp(1001, server_isn.wrapping_add(1), 0x10, b"")]);
    device.push(&[&client.tcp(1001, server_isn.wrapping_add(1), 0x18, b"bye")]);
    let deadline = Instant::now() + Duration::from_secs(5);
    while handle.live_sessions() > 0 {
        assert!(Instant::now() < deadline, "the session never ended");
        std::thread::sleep(Duration::from_millis(10));
    }
    seen.clear();

    handle.stop();
    let mut probe = device.duplicate().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while probe.write_batch(&mut []).is_ok() {
        assert!(
            Instant::now() < deadline,
            "the stop never closed the device"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    seen.extend(device.take_written().iter().filter_map(|p| segment(p)));
    assert!(
        seen.iter().all(|s| s.flags & 0x04 == 0),
        "no reset for a flow whose stream is gone"
    );
}
