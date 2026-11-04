// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Micro-benchmarks for the stack's own hot core: one segment through
//! the state machine, the emit path that builds its reply frame, and
//! the accept layer's cookie ISN. These are the numbers the weekly CI
//! baseline compares, so a regression in the TCP engine's per-segment
//! cost cannot land quietly.

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use vfawn_core::{FlowInfo, IcmpPacket, Network};
use vfawn_stack_user::CongestionAlgo as _;
use vfawn_stack_user::FixedSecret;
use vfawn_stack_user::Inbound;
use vfawn_stack_user::ServerConnection;
use vfawn_stack_user::accept::AcceptQueue;
use vfawn_stack_user::{Cubic, Reno};

/// A SYN that opens a connection (the state machine's entry cost).
fn syn_segment() -> Inbound<'static> {
    Inbound {
        seq: 5000,
        ack: 0,
        flags: 0x02,
        window: 65535,
        options: Default::default(),
        payload: &[],
    }
}

/// The completing ACK.
fn ack_segment(una: u32) -> Inbound<'static> {
    Inbound {
        seq: 5001,
        ack: una,
        flags: 0x10,
        window: 65535,
        options: Default::default(),
        payload: &[],
    }
}

/// One in-order data segment carrying 536 bytes (the default MSS).
fn data_segment(seq: u32, ack: u32) -> Inbound<'static> {
    Inbound {
        seq,
        ack,
        flags: 0x18,
        window: 65535,
        options: Default::default(),
        payload: &[0x41; 536],
    }
}

fn established() -> ServerConnection {
    let mut connection = ServerConnection::new(1000, 536);
    let _ = connection.on_segment(&syn_segment());
    let _ = connection.on_segment(&ack_segment(1001));
    connection
}

fn bench_stack(c: &mut Criterion) {
    c.bench_function("tcp_handshake_open", |b| {
        b.iter(|| {
            let mut connection = ServerConnection::new(1000, 536);
            let syn = syn_segment();
            let _ = std::hint::black_box(connection.on_segment(&syn));
        })
    });

    c.bench_function("tcp_segment_in_order", |b| {
        b.iter_batched(
            established,
            |mut connection| {
                let mut next = connection.send_nxt();
                let _ = std::hint::black_box({
                    let seg = data_segment(next, 1001);
                    let reaction = connection.on_segment(&seg);
                    next = next.wrapping_add(536);
                    reaction
                });
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("tcp_out_of_order_hold", |b| {
        b.iter_batched(
            established,
            |mut connection| {
                // The second segment arrives first: held above the gap,
                // then the first fills it and both deliver.
                let held = data_segment(1002, 1001);
                let fill = data_segment(1001, 1001);
                let r1 = connection.on_segment(&held);
                let r2 = connection.on_segment(&fill);
                (r1.delivered.len(), r2.delivered.len())
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("cookie_isn_for_new_flow", |b| {
        let queue = AcceptQueue::new(true, 128, Box::new(FixedSecret(0xC0FFEE)));
        let base: std::net::SocketAddr = "192.0.2.1:40000".parse().unwrap();
        b.iter(|| {
            let mut issued = 0u64;
            for port in 40000u16..40064 {
                let _ = queue.sequence_for(
                    format!("192.0.2.1:{port}").parse().unwrap(),
                    std::time::Instant::now(),
                );
                issued += u64::from(port);
            }
            std::hint::black_box(issued);
            let _ = base;
        })
    });

    c.bench_function("cc_cubic_ack_growth", |b| {
        b.iter(|| {
            let mut cubic = Cubic::new(536);
            for _ in 0..1000 {
                cubic.on_signal(
                    536,
                    vfawn_stack_user::Signal::Acked {
                        newly: 536,
                        rtt: None,
                    },
                );
            }
            cubic.window()
        })
    });

    c.bench_function("cc_reno_timeout_cycle", |b| {
        b.iter(|| {
            let mut reno = Reno::new(536);
            for round in 0..50 {
                for _ in 0..(1 << round.min(6)) {
                    reno.on_signal(
                        536,
                        vfawn_stack_user::Signal::Acked {
                            newly: 536,
                            rtt: None,
                        },
                    );
                }
                reno.on_signal(536, vfawn_stack_user::Signal::Timeout);
            }
            reno.window()
        })
    });
}

fn bench_icmp(c: &mut Criterion) {
    let flow = FlowInfo {
        network: Network::Icmp,
        source: "192.0.2.1:0".parse().unwrap(),
        destination: "10.0.0.1:0".parse().unwrap(),
    };
    // An echo request with a valid checksum.
    let mut message = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 1];
    message.extend_from_slice(b"payload");
    let sum = vfawn_wire::checksum::sum_words(&message);
    message[2..4].copy_from_slice(&(!vfawn_wire::checksum::fold(sum)).to_be_bytes());
    let packet = IcmpPacket::new(flow, 8, 0, Bytes::from(message)).with_ttl(64);

    c.bench_function("icmp_echo_classify", |b| {
        b.iter(|| vfawn_stack_user::IcmpVerdict::from(std::hint::black_box(&packet)))
    });

    // A quoted error datagram for the correlation path.
    let mut quote = vec![0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 64, 6, 0, 0];
    quote.extend_from_slice(&[192, 168, 1, 100]);
    quote.extend_from_slice(&[203, 0, 113, 2]);
    quote.extend_from_slice(&0x1234u16.to_be_bytes());
    quote.extend_from_slice(&0x0050u16.to_be_bytes());
    let mut error = vec![3u8, 4, 0, 0, 0, 0, 0, 0];
    error.extend_from_slice(&quote);
    let error_flow = FlowInfo {
        network: Network::Icmp,
        source: "203.0.113.1:0".parse().unwrap(),
        destination: "192.168.1.100:0".parse().unwrap(),
    };
    let error_packet = IcmpPacket::new(error_flow, 3, 4, Bytes::from(error));

    c.bench_function("icmp_error_correlate", |b| {
        b.iter(|| vfawn_stack_user::IcmpVerdict::from(std::hint::black_box(&error_packet)))
    });
}

criterion_group!(benches, bench_stack, bench_icmp);
criterion_main!(benches);
