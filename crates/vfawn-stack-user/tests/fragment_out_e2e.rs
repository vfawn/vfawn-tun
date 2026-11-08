// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The egress half of the fragment story: a reply larger than the
//! device's MTU leaves as IP fragments and recombines, on the wire
//! capture, into exactly the datagram the session wrote.

#![cfg(feature = "backend-native")]

use std::net::{Ipv4Addr, SocketAddrV4};

use bytes::BytesMut;
use vfawn_core::{DeviceCaps, PacketDevice};
use vfawn_stack_user::{ShardConfig, Shards};
use vfawn_testsuite::{MockDevice, Script};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45000);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 7000);
const MTU: usize = 1500;

/// An echo that mirrors the whole packet: the skeleton's own UdpEcho
/// truncates to the MTU (a device-bound answer), while this test wants
/// the full datagram to meet the writer's splitting.
struct WholeEcho;

impl vfawn_stack_user::SlotLogic for WholeEcho {
    fn on_packet(
        &mut self,
        packet: &[u8],
        out: &mut std::collections::VecDeque<BytesMut>,
        pool: &vfawn_stack_user::shards::BufferPool,
        mtu: usize,
    ) {
        let mut reply = pool.packet(mtu.max(packet.len()));
        reply.clear();
        reply.extend_from_slice(packet);
        for index in 0..4 {
            reply.swap(12 + index, 16 + index);
        }
        out.push_back(reply);
    }
}

fn start() -> (Shards, MockDevice) {
    let device = MockDevice::new(DeviceCaps::MINIMAL);
    let shards = Shards::start(
        device.duplicate().unwrap(),
        device.duplicate().unwrap(),
        ShardConfig {
            shards: 1,
            mtu: MTU,
            ..ShardConfig::default()
        },
        std::sync::Arc::new(|_| Box::new(WholeEcho)),
        std::sync::Arc::new(vfawn_stack_user::shards::BufferPool::new()),
    );
    (shards, device)
}

fn wait_for_frames(device: &MockDevice, minimum: usize) -> Vec<Vec<u8>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let written = device.take_written();
        if written.len() >= minimum || std::time::Instant::now() > deadline {
            return written;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Stack the fragments of one captured exchange back into the payload
/// the session echoed.
fn recombine(frames: &[Vec<u8>]) -> Option<Vec<u8>> {
    let mut by_offset: Vec<(usize, &[u8])> = Vec::new();
    let mut head: Option<&[u8]> = None;
    for frame in frames {
        if frame.len() < 20 || frame[0] >> 4 != 4 {
            continue;
        }
        let ihl = (frame[0] as usize & 0x0f) * 4;
        let field = u16::from_be_bytes([frame[6], frame[7]]);
        if field & 0x1fff == 0 {
            head = Some(frame);
        } else {
            by_offset.push(((field & 0x1fff) as usize * 8, &frame[ihl..]));
        }
    }
    let head = head?;
    let ihl = (head[0] as usize & 0x0f) * 4;
    let mut payload = head[ihl..].to_vec();
    for (offset, piece) in by_offset {
        if payload.len() < offset + piece.len() {
            payload.resize(offset + piece.len(), 0);
        }
        payload[offset..offset + piece.len()].copy_from_slice(piece);
    }
    Some(payload)
}

#[test]
fn an_oversize_reply_leaves_as_fragments_and_recombines() {
    let (shards, device) = start();
    let script = Script::new(CLIENT, SERVER);

    // 3000 payload bytes through a 1500 MTU: the echo comes back as
    // three IP fragments.
    let payload: Vec<u8> = (0..3000).map(|index| (index % 253) as u8).collect();
    let request = script.udp(&payload);
    assert!(
        request.len() > MTU,
        "the request itself would need inbound care; this test drives the reply"
    );
    // The inbound side is the reassembler's own test; here push the
    // request as one oversized frame — the mock device carries it, and
    // the echo's outbound path is what this test measures.
    device.push(&[&request]);

    let frames = wait_for_frames(&device, 3);
    shards.stop();

    assert!(
        frames.iter().all(|frame| frame.len() <= MTU),
        "every frame fits the MTU: {:?}",
        frames.iter().map(|f| f.len()).collect::<Vec<_>>()
    );
    let fragments: Vec<&Vec<u8>> = frames
        .iter()
        .filter(|f| f.len() >= 20 && f[0] >> 4 == 4)
        .collect();
    assert!(fragments.len() >= 2, "the reply left as fragments");
    let recombined = recombine(&frames).expect("a head and its pieces");
    // The echo mirrors the payload: the UDP header rides the head
    // fragment (8 bytes), the payload follows.
    assert_eq!(recombined.len(), 8 + payload.len());
    assert_eq!(&recombined[8..], &payload[..]);
    let _ = BytesMut::new();
}
