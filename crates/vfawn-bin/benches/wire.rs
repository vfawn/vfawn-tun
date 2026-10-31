// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Micro-benchmarks for the packet parsing hot path: wire header decode
//! and flow key extraction.

use criterion::{Criterion, criterion_group, criterion_main};
use vfawn_wire::flow::flow_key;
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::tcp::TcpHeader;
use vfawn_wire::udp::UdpHeader;

/// A minimal well-formed IPv4+TCP packet with correct checksums.
fn tcp_packet() -> Vec<u8> {
    let src: [u8; 4] = [192, 168, 1, 100];
    let dst: [u8; 4] = [10, 0, 0, 1];
    let sport: u16 = 45678;
    let dport: u16 = 443;
    let seq: u32 = 1000;
    let ack: u32 = 2000;

    let mut packet = Vec::with_capacity(40);
    // IPv4 header.
    packet.extend_from_slice(&[0x45, 0x00, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    // TCP header.
    packet.extend_from_slice(&sport.to_be_bytes());
    packet.extend_from_slice(&dport.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&ack.to_be_bytes());
    packet.extend_from_slice(&[0x50, 0x10, 0xFF, 0xFF, 0, 0, 0, 0]);
    packet
}

/// A minimal IPv4+UDP packet.
fn udp_packet() -> Vec<u8> {
    let src: [u8; 4] = [192, 168, 1, 100];
    let dst: [u8; 4] = [10, 0, 0, 1];
    let mut packet = Vec::with_capacity(28);
    packet.extend_from_slice(&[0x45, 0x00, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(&50000u16.to_be_bytes());
    packet.extend_from_slice(&53u16.to_be_bytes());
    packet.extend_from_slice(&8u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet
}

fn bench_wire(c: &mut Criterion) {
    let tcp = tcp_packet();
    let udp = udp_packet();

    c.bench_function("ipv4_header_parse", |b| {
        b.iter(|| {
            let (header, _) = Ipv4Header::parse(&tcp).unwrap();
            std::hint::black_box(header.protocol);
        })
    });

    c.bench_function("tcp_header_parse", |b| {
        b.iter(|| {
            let (_, payload) = Ipv4Header::parse(&tcp).unwrap();
            let (header, _) = TcpHeader::parse(payload).unwrap();
            std::hint::black_box(header.flags);
        })
    });

    c.bench_function("udp_header_parse", |b| {
        b.iter(|| {
            let (_, payload) = Ipv4Header::parse(&udp).unwrap();
            let (header, _) = UdpHeader::parse(payload).unwrap();
            std::hint::black_box(header.dst_port);
        })
    });

    c.bench_function("flow_key_tcp", |b| {
        b.iter(|| {
            let key = flow_key(&tcp).unwrap();
            std::hint::black_box(key.src_port);
        })
    });

    c.bench_function("flow_key_udp", |b| {
        b.iter(|| {
            let key = flow_key(&udp).unwrap();
            std::hint::black_box(key.dst_port);
        })
    });
}

criterion_group!(benches, bench_wire);
criterion_main!(benches);
