// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Throughput measurement for the packet-processing hot path.
//!
//! Two numbers, both platform-independent:
//!
//! * **Parse rate**: how many IPv4+TCP header parses per second the wire
//!   crate sustains. This is the per-packet floor the data plane pays
//!   before any stack logic runs.
//! * **Flow key rate**: how many five-tuple extractions per second. This
//!   is what the dispatcher does per packet to pick a shard.
//!
//! For connection-cycle rate against the full stack (SYN to FIN), the
//! harness needs a TUN device and runs under Linux with the 008 script;
//! these numbers are the deterministic component that can be compared
//! across machines and CI runs.

use std::time::Instant;
use vfawn_wire::flow::flow_key;
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::tcp::TcpHeader;

pub fn run() {
    println!("vfawn packet-processing benchmark");
    println!("==================================");

    let rounds = 5;
    let packets_per_round = 100_000;

    let mut parse_rates = Vec::with_capacity(rounds);
    let mut key_rates = Vec::with_capacity(rounds);

    for round in 1..=rounds {
        let (parse_rps, key_rps) = one_round(packets_per_round);
        parse_rates.push(parse_rps);
        key_rates.push(key_rps);
        println!(
            "  round {}/{}: parse {:>8.0} pkt/s, flow_key {:>8.0} pkt/s",
            round, rounds, parse_rps, key_rps
        );
    }

    let parse_median = median(&parse_rates);
    let key_median = median(&key_rates);
    println!();
    println!("  median parse:   {:>10.0} pkt/s", parse_median);
    println!("  median flow_key:{:>10.0} pkt/s", key_median);
    println!();
    println!("criterion micro-benchmarks: cargo bench -p vfawn-bin");
}

/// Build a batch of packets, then measure parse and key-extract rates.
fn one_round(count: usize) -> (f64, f64) {
    let packets = build_batch(count);

    // Measure header parsing.
    let start = Instant::now();
    for packet in &packets {
        let (ip, payload) = Ipv4Header::parse(packet).expect("parse");
        let (tcp, _) = TcpHeader::parse(payload).expect("parse");
        std::hint::black_box((ip.protocol, tcp.src_port));
    }
    let parse_elapsed = start.elapsed();

    // Measure flow key extraction (includes the same parsing internally).
    let start = Instant::now();
    for packet in &packets {
        let key = flow_key(packet).expect("key");
        std::hint::black_box(key.src_port);
    }
    let key_elapsed = start.elapsed();

    (
        count as f64 / parse_elapsed.as_secs_f64(),
        count as f64 / key_elapsed.as_secs_f64(),
    )
}

/// Build a batch of minimal IPv4+TCP packets with correct framing.
fn build_batch(count: usize) -> Vec<Vec<u8>> {
    let src: [u8; 4] = [192, 168, 1, 100];
    let dst: [u8; 4] = [10, 0, 0, 1];
    (0..count)
        .map(|i| {
            let mut p = Vec::with_capacity(40);
            p.extend_from_slice(&[
                0x45,
                0x00,
                0,
                40,
                (i >> 8) as u8,
                i as u8,
                0,
                0,
                64,
                6,
                0,
                0,
            ]);
            p.extend_from_slice(&src);
            p.extend_from_slice(&dst);
            p.extend_from_slice(&(45678u16 + (i % 1000) as u16).to_be_bytes());
            p.extend_from_slice(&443u16.to_be_bytes());
            p.extend_from_slice(&1000u32.to_be_bytes());
            p.extend_from_slice(&2000u32.to_be_bytes());
            p.extend_from_slice(&[0x50, 0x10, 0xFF, 0xFF, 0, 0, 0, 0]);
            p
        })
        .collect()
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    sorted[sorted.len() / 2]
}
