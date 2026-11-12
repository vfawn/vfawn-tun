// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A stopping native stack resets the connections it still holds, and
//! the resets reach the device before it closes: sing-tun's `Close`
//! detaches the reader, aborts every registered endpoint — a connected
//! one sends `<SEQ=SND.NXT><ACK=RCV.NXT><RST,ACK>` (gVisor
//! `connect.go:1069-1088`), a handshake still in SYN-RECEIVED only
//! closes (`endpoint.go:1035-1047`) — and the tun closes after
//! (`stack_gvisor.go:123-136`). Without the reset a client holding the
//! connection reads on until its own timeout.

#![cfg(feature = "backend-native")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vfawn_core::{
    Action, DeviceCaps, FlowInfo, IcmpPacket, PacketDevice, SessionHandler, StackBackend,
    TcpSession, UdpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_stack_user::shards::{BufferPool, ShardConfig, Shards, SlotLogic};
use vfawn_testsuite::{MockDevice, Script};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const HALF_OPEN: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45679);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

const GREETING: &[u8] = b"hello";

/// Greets, then holds the connection open reading until it ends: the
/// relay a client keeps a connection through.
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
        let _ = session.write(GREETING).await;
        let mut buf = [0u8; 4096];
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
/// flags, cursors and payload (IPv4 without options, as the stack
/// emits them).
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
    let tcp = packet.get(ihl..)?;
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
    let handle = Box::new(NativeBackend::default())
        .spawn(device.duplicate().unwrap(), handler.clone())
        .expect("spawn native backend");
    let mut seen = Vec::new();

    // One connection established, with bytes both ways.
    let client = Script::new(CLIENT, SERVER);
    device.push(&[&client.tcp(1000, 0, 0x02, b"")]);
    let synack = wait_for_segment(&device, &mut seen, "SYN-ACK", |s| {
        s.client_port == CLIENT.port() && s.flags & 0x12 == 0x12
    });
    let server_isn = seen[synack].seq;
    let request = b"ping";
    device.push(&[
        &client.tcp(1001, server_isn.wrapping_add(1), 0x10, b""),
        &client.tcp(1001, server_isn.wrapping_add(1), 0x18, request),
    ]);
    wait_for_segment(&device, &mut seen, "the greeting", |s| {
        s.client_port == CLIENT.port() && s.payload == GREETING
    });
    assert_eq!(handler.sessions.load(Ordering::SeqCst), 1);
    // SND.NXT past the SYN and the greeting; RCV.NXT past the request.
    let send_nxt = server_isn
        .wrapping_add(1)
        .wrapping_add(GREETING.len() as u32);
    let recv_nxt = 1001 + request.len() as u32;

    // A second flow left in SYN-RECEIVED: gVisor closes it unannounced.
    let half_open = Script::new(HALF_OPEN, SERVER);
    device.push(&[&half_open.tcp(5000, 0, 0x02, b"")]);
    wait_for_segment(&device, &mut seen, "the half-open SYN-ACK", |s| {
        s.client_port == HALF_OPEN.port() && s.flags & 0x12 == 0x12
    });
    seen.clear();

    handle.stop();

    // The device closes once the stack is done with it; a closed mock
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
}

/// A slot whose abort takes its time before owing the wire a frame:
/// the stop's reset arriving late, as a busy shard's would.
struct SlowAbort;

const LATE_FRAME: &[u8] = b"owed at the stop";

impl SlotLogic for SlowAbort {
    fn on_packet(
        &mut self,
        _packet: &[u8],
        _out: &mut std::collections::VecDeque<bytes::BytesMut>,
        _pool: &BufferPool,
        _mtu: usize,
    ) {
    }

    fn abort(&mut self, out: &mut std::collections::VecDeque<bytes::BytesMut>) {
        std::thread::sleep(Duration::from_millis(100));
        out.push_back(bytes::BytesMut::from(LATE_FRAME));
    }
}

/// The close waits for the aborts however long they take: the device
/// closes after the last shard has left and its frames are written,
/// never on the stop itself (sing-tun closes the stack before the tun,
/// `stack_gvisor.go:123-136`). A pipeline that closed the device as the
/// stop arrived would refuse the late frame.
#[test]
fn the_device_closes_after_the_aborts_are_written() {
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let shards = Shards::start(
        device.duplicate().unwrap(),
        device.duplicate().unwrap(),
        ShardConfig {
            shards: 2,
            mtu: 1500,
            ..ShardConfig::default()
        },
        Arc::new(|_: &vfawn_wire::flow::FlowKey| Box::new(SlowAbort) as Box<dyn SlotLogic>),
        Arc::new(BufferPool::new()),
    );
    device.push(&[&Script::new(CLIENT, SERVER).udp(b"open a slot")]);
    let deadline = Instant::now() + Duration::from_secs(5);
    while shards
        .processed
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .sum::<u64>()
        == 0
    {
        assert!(
            Instant::now() < deadline,
            "the packet never reached a shard"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    // Stop and join every thread: the device is closed by the time the
    // drop returns, and a closed mock refuses every write.
    drop(shards);
    let mut probe = device.duplicate().unwrap();
    assert!(
        probe.write_batch(&mut []).is_err(),
        "the stopped pipeline closed the device"
    );
    assert_eq!(
        device.take_written(),
        vec![LATE_FRAME.to_vec()],
        "the abort's frame was written before the close"
    );
}
