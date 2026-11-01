// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Micro-benchmarks for the shard dispatch hot path: how much a packet
//! costs to classify (flow key plus shard hash) before any stack work
//! begins, and what the lock-free ring hand-off adds on top.

use bytes::BytesMut;
use criterion::{Criterion, criterion_group, criterion_main};
use vfawn_stack_user::shards::{Ring, shard_hash_of};
use vfawn_wire::flow::flow_key;

fn udp_packet(port: u16) -> Vec<u8> {
    let src: [u8; 4] = [192, 168, 1, 100];
    let dst: [u8; 4] = [10, 0, 0, 1];

    let mut packet = Vec::with_capacity(28);
    // IPv4 header.
    packet.extend_from_slice(&[0x45, 0x00, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    // UDP header.
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(&7000u16.to_be_bytes());
    packet.extend_from_slice(&8u16.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet
}

fn bench_dispatch(c: &mut Criterion) {
    let packets: Vec<Vec<u8>> = (0..64).map(|port| udp_packet(40000 + port)).collect();

    c.bench_function("shard_classify", |b| {
        b.iter(|| {
            let mut shard = 0;
            for packet in &packets {
                let key = flow_key(packet).expect("valid packet");
                shard ^= shard_hash_of(&key, 8);
            }
            std::hint::black_box(shard);
        })
    });

    c.bench_function("ring_roundtrip_64_batches", |b| {
        let ring = Ring::new(128);
        b.iter(|| {
            for _ in 0..64 {
                let batch = vec![BytesMut::from(&[0u8; 32][..])];
                ring.try_push(batch).expect("room");
            }
            let mut drained: usize = 0;
            while let Some(batch) = ring.pop() {
                drained += batch.len();
            }
            std::hint::black_box(drained);
        })
    });
}

criterion_group!(benches, bench_dispatch);
criterion_main!(benches);
