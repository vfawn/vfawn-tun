// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A timing probe (not an assertion test): one established connection,
//! a scripted acknowledgment stream, and the per-ACK and per-segment
//! costs of the slow path named in nanoseconds. The downlink's binding
//! constraint lives in the drain; this file exists to point at the
//! line that costs.

#![cfg(feature = "backend-native")]

use bytes::BytesMut;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;
use vfawn_stack_user::native_backend::cost_probe_support::{
    refill_lane, send_cursor, slot_for_cost_probe,
};
use vfawn_stack_user::shards::{BufferPool, SlotLogic};

#[expect(clippy::too_many_arguments)]
fn v4_packet(
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + 20 + payload.len();
    let mut packet = Vec::with_capacity(total);
    packet.extend_from_slice(&[0x45, 0x00]);
    packet.extend_from_slice(&(total as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(&sport.to_be_bytes());
    packet.extend_from_slice(&dport.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&ack.to_be_bytes());
    packet.push(5 << 4);
    packet.push(flags);
    packet.extend_from_slice(&64u16.to_be_bytes());
    packet.extend_from_slice(&[0; 4]);
    packet.extend_from_slice(payload);
    packet
}

#[test]
fn per_ack_and_per_segment_costs_of_the_slow_path() {
    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);
    let mut slot = slot_for_cost_probe();
    let pool = Arc::new(BufferPool::new());
    let mut out: VecDeque<BytesMut> = VecDeque::new();

    // Handshake to ESTABLISHED, then one payload segment so the flight
    // and the congestion controller carry state.
    let syn = v4_packet(client_ip, 44444, server_ip, 443, 1000, 0, 0x02, b"");
    slot.on_packet(&syn, &mut out, &pool, 1500);
    let server_isn = 2000u32;
    let hs_ack = v4_packet(
        client_ip,
        44444,
        server_ip,
        443,
        1001,
        server_isn.wrapping_add(1),
        0x10,
        b"",
    );
    slot.on_packet(&hs_ack, &mut out, &pool, 1500);
    let payload = vec![0u8; 100];
    let data = v4_packet(
        client_ip,
        44444,
        server_ip,
        443,
        1001,
        server_isn.wrapping_add(1),
        0x18,
        &payload,
    );
    slot.on_packet(&data, &mut out, &pool, 1500);
    out.clear();

    // The acknowledgment stream: each entry advances the server's send
    // floor by a segment, exactly the downlink's inbound shape.
    const ROUNDS: usize = 200_000;
    let mut acks = Vec::with_capacity(ROUNDS);
    for i in 0..ROUNDS {
        acks.push(v4_packet(
            client_ip,
            44444,
            server_ip,
            443,
            1001 + payload.len() as u32,
            server_isn.wrapping_add(2 + (i as u32) * 1460),
            0x10,
            b"",
        ));
    }
    for ack in acks.iter().take(1000) {
        slot.on_packet(ack, &mut out, &pool, 1500);
    }
    out.clear();
    let start = Instant::now();
    for ack in acks.iter() {
        slot.on_packet(ack, &mut out, &pool, 1500);
    }
    let per_ack = start.elapsed().as_nanos() / ROUNDS as u128;
    eprintln!("PER-ACK (idle lane): {per_ack} ns");

    // The drain's cost: the lane carries real bytes, each pass's
    // acknowledgment reopens the window, and the emit builds the frame
    // — header, checksum, pool buffer — the work the downlink shard
    // actually spends its core on.
    let mut segments: u64 = 0;
    let mut drain_ns: u128 = 0;
    let mut acks_used = 0usize;
    for _ in 0..200 {
        refill_lane(&mut slot, 200_000);
        let before = out.len();
        let round_start = Instant::now();
        for _ in 0..200 {
            // Acknowledge exactly what has been sent: the send cursor
            // names it, the window reopens to its fullest.
            let (nxt, _una) = send_cursor(&slot);
            let ack = v4_packet(
                client_ip,
                44444,
                server_ip,
                443,
                1001 + payload.len() as u32,
                nxt,
                0x10,
                b"",
            );
            slot.on_packet(&ack, &mut out, &pool, 1500);
            acks_used += 1;
        }
        drain_ns += round_start.elapsed().as_nanos();
        segments += (out.len() - before) as u64;
    }
    let _ = acks_used;
    let frames = out.len() as u64;
    out.clear();
    if segments > 0 {
        eprintln!(
            "PER-SEGMENT (lane-driven): {} ns over {segments} segments ({frames} frames)",
            drain_ns / segments as u128
        );
    } else {
        eprintln!("PER-SEGMENT: none emitted — window never reopened?");
    }
}
