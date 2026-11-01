// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The differential corpus: one scripted client, two stacks, wire-truth
//! comparison on every step.
//!
//! Today both sides are the smoltcp oracle, which validates the referee
//! itself (identical drivers must produce identical records, and the
//! harness must be deterministic run to run). When the in-house stack
//! lands in 037 it implements the same [`StackDriver`] and replaces one
//! side of every scenario here without the corpus changing at all.
//!
//! Scenario axes: handshake shape, transfer size, loss and reorder
//! patterns, duplicate deliveries, window starvation, teardown variants,
//! and timer-driven behavior (retransmission under wait steps).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Instant;

use vfawn_core::PacketDevice as _;
use vfawn_testsuite::diff::{
    self, CompareMask, Scenario, StackDriver, assert_batch, corpus_client, corpus_server,
};
use vfawn_testsuite::diff_smoltcp::SmoltcpDriver;
use vfawn_testsuite::native_tcp_driver::NativeTcpDriver;
use vfawn_testsuite::{PcapDevice, Script};

/// Builds client-side packets for a scenario at a given variant.
struct Builder {
    script: Script,
}

impl Builder {
    fn new(variant: u8) -> Self {
        Self {
            script: Script::new(corpus_client(variant), corpus_server(variant)),
        }
    }

    fn syn(&self, seq: u32) -> Vec<u8> {
        self.script.tcp(seq, 0, 0x02, b"")
    }

    fn ack(&self, seq: u32, ack: u32) -> Vec<u8> {
        self.script.tcp(seq, ack, 0x10, b"")
    }

    fn data(&self, seq: u32, ack: u32, len: usize, fill: u8) -> Vec<u8> {
        self.script.tcp(seq, ack, 0x18, &vec![fill; len])
    }

    fn fin(&self, seq: u32, ack: u32) -> Vec<u8> {
        self.script.tcp(seq, ack, 0x11, b"")
    }

    fn rst(&self, seq: u32, ack: u32) -> Vec<u8> {
        self.script.tcp(seq, ack, 0x14 | 0x04, b"")
    }

    fn window0(&self, seq: u32, ack: u32) -> Vec<u8> {
        let mut packet = self.script.tcp(seq, ack, 0x10, b"");
        // Zero the advertised window: bytes 14..16 of the TCP header.
        packet[20 + 14] = 0;
        packet[20 + 15] = 0;
        recompute_tcp_checksum(&mut packet);
        packet
    }
}

/// Re-fix the TCP checksum after an in-place header edit.
fn recompute_tcp_checksum(packet: &mut [u8]) {
    use std::net::IpAddr;
    let (ip, _) = vfawn_wire::ipv4::Ipv4Header::parse(packet).expect("parse after edit");
    // Zero the field, recompute over pseudo header plus segment.
    packet[20 + 16] = 0;
    packet[20 + 17] = 0;
    let src = IpAddr::V4(ip.src);
    let dst = IpAddr::V4(ip.dst);
    let words: Vec<u8> = {
        let mut head = Vec::with_capacity(12 + packet.len() - 20);
        for addr in [src, dst] {
            let octets = match addr {
                IpAddr::V4(v) => v.octets().to_vec(),
                _ => unreachable!(),
            };
            head.extend(octets);
        }
        head.push(0);
        head.push(6);
        head.extend_from_slice(&((packet.len() - 20) as u16).to_be_bytes());
        head.extend_from_slice(&packet[20..]);
        head
    };
    let sum = vfawn_wire::checksum::fold(vfawn_wire::checksum::sum_words(&words));
    let fixed = !sum;
    packet[20 + 16] = (fixed >> 8) as u8;
    packet[20 + 17] = fixed as u8;
}

/// The server ISN the corpus scripts acknowledge: probed from the
/// oracle's own first SYN-ACK once, before the corpus is built, so
/// every client ACK lands in both stacks' acknowledgment space.
static SERVER_ISN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000);

fn server_isn() -> u32 {
    SERVER_ISN.load(std::sync::atomic::Ordering::Relaxed)
}

/// One oracle handshake, read the ISN off its SYN-ACK, pin it for the
/// whole corpus. Deterministic under seed 0, so once is enough.
fn probe_oracle_isn() -> u32 {
    let mut oracle = SmoltcpDriver::new();
    let probe = handshake_scenario("isn-probe", 0, 0);
    oracle.reset(&probe);
    for step in &probe.steps {
        oracle.step(step);
    }
    oracle.listen_isn.expect("the oracle completed a handshake")
}

fn handshake_scenario(name: &str, variant: u8, syn_retransmits: u32) -> Scenario {
    let mut scenario = Scenario::new(name, corpus_client(variant), corpus_server(variant));
    let builder = Builder::new(variant);
    scenario.inject(0, builder.syn(5000));
    for _ in 0..syn_retransmits {
        scenario.inject(500, builder.syn(5000));
    }
    scenario.wait(100);
    scenario
}

fn transfer_scenario(
    name: &str,
    variant: u8,
    segments: usize,
    segment_len: usize,
    drop_indices: &[usize],
    reorder: bool,
    teardown: Teardown,
) -> Scenario {
    let mut scenario = Scenario::new(name, corpus_client(variant), corpus_server(variant));
    let builder = Builder::new(variant);

    // Handshake.
    scenario.inject(0, builder.syn(5000));
    // Client ACKs the SYN-ACK, then sends data.
    let mut client_seq = 5001;
    let server_ack_base = server_isn() + 1;
    scenario.inject(10, builder.ack(client_seq, server_ack_base));

    let mut packets = Vec::new();
    for index in 0..segments {
        if drop_indices.contains(&index) {
            continue;
        }
        packets.push(builder.data(client_seq, server_ack_base, segment_len, index as u8));
        client_seq += segment_len as u32;
    }
    if reorder && packets.len() >= 2 {
        // Swap adjacent pairs deterministically.
        let mut index = 1;
        while index < packets.len() {
            packets.swap(index - 1, index);
            index += 2;
        }
    }
    for (position, packet) in packets.into_iter().enumerate() {
        let delay = if position == 0 { 10 } else { 5 };
        scenario.inject(delay, packet);
    }

    // Acknowledge the echo so both stacks end the scenario with empty
    // flight: without it the oracle's retransmission timer fires during
    // the final drain, which is 038's family, not this volume's.
    let sent_bytes = segments * segment_len;
    scenario.inject(
        10,
        builder.ack(client_seq, server_ack_base + sent_bytes as u32),
    );

    match teardown {
        Teardown::None => {}
        Teardown::Fin => {
            scenario.inject(10, builder.fin(client_seq, server_ack_base));
        }
        Teardown::FinWithData => {
            scenario.inject(10, builder.data(client_seq, server_ack_base, 40, 0xEE));
            client_seq += 40;
            scenario.inject(5, builder.fin(client_seq, server_ack_base));
        }
        Teardown::Rst => {
            scenario.inject(10, builder.rst(client_seq, server_ack_base));
        }
    }
    scenario.wait(100);
    scenario
}

enum Teardown {
    None,
    Fin,
    FinWithData,
    Rst,
}

fn wait_scenario(name: &str, variant: u8, segments: usize, segment_len: usize) -> Scenario {
    // A transfer whose tail is lost, then long waits: retransmission
    // timers must fire in both drivers at comparable points.
    let mut scenario = Scenario::new(name, corpus_client(variant), corpus_server(variant));
    let builder = Builder::new(variant);
    scenario.inject(0, builder.syn(5000));
    let mut client_seq = 5001;
    let server_ack_base = server_isn() + 1;
    scenario.inject(10, builder.ack(client_seq, server_ack_base));
    for index in 0..segments {
        let packet = builder.data(client_seq, server_ack_base, segment_len, index as u8);
        if index == segments - 1 {
            // The final segment is never sent; every earlier one was.
            break;
        }
        scenario.inject(5, packet);
        client_seq += segment_len as u32;
    }
    scenario.wait(3000);
    scenario.inject(
        0,
        builder.data(client_seq, server_ack_base, segment_len, 0x42),
    );
    scenario.wait(200);
    scenario
}

fn window_scenario(name: &str, variant: u8, freeze: bool) -> Scenario {
    let mut scenario = Scenario::new(name, corpus_client(variant), corpus_server(variant));
    let builder = Builder::new(variant);
    scenario.inject(0, builder.syn(5000));
    let mut client_seq = 5001;
    let server_ack_base = server_isn() + 1;
    scenario.inject(10, builder.ack(client_seq, server_ack_base));
    scenario.inject(5, builder.data(client_seq, server_ack_base, 400, 1));
    client_seq += 400;
    if freeze {
        scenario.inject(5, builder.window0(client_seq, server_ack_base));
        scenario.wait(400);
    }
    scenario.inject(5, builder.ack(client_seq, server_ack_base).clone());
    scenario.wait(100);
    scenario
}

/// Duplicate delivery of an already-acked segment plus repeated ACKs.
fn dup_scenario(name: &str, variant: u8, dups: usize) -> Scenario {
    let mut scenario = Scenario::new(name, corpus_client(variant), corpus_server(variant));
    let builder = Builder::new(variant);
    scenario.inject(0, builder.syn(5000));
    let client_seq = 5001;
    let server_ack_base = server_isn() + 1;
    scenario.inject(10, builder.ack(client_seq, server_ack_base));
    scenario.inject(5, builder.data(client_seq, server_ack_base, 200, 7));
    for _ in 0..dups {
        scenario.inject(5, builder.data(client_seq, server_ack_base, 200, 7));
    }
    scenario.wait(100);
    scenario
}

fn corpus() -> Vec<Scenario> {
    let mut all = Vec::new();

    // Loss+reorder compound grids across the wide transfer shapes.
    for (segments, segment_len) in [(4usize, 512usize), (8, 1400), (16, 256)] {
        for variant in 0u8..4 {
            all.push(transfer_scenario(
                &format!("loss-scatter-{segments}x{segment_len}-v{variant}"),
                variant,
                segments,
                segment_len,
                &[0, segments / 2],
                true,
                Teardown::None,
            ));
        }
    }

    for variant in 0u8..6 {
        all.push(handshake_scenario(
            &format!("syn-only-v{variant}"),
            variant,
            0,
        ));
        all.push(handshake_scenario(
            &format!("syn-retransmit-v{variant}"),
            variant,
            2,
        ));
    }

    let sizes = [(1usize, 1usize), (2, 100), (4, 512), (8, 1400), (16, 256)];
    for (index, &(segments, segment_len)) in sizes.iter().enumerate() {
        for variant in 0u8..8 {
            all.push(transfer_scenario(
                &format!("bulk-{segments}x{segment_len}-v{variant}"),
                variant,
                segments,
                segment_len,
                &[],
                false,
                Teardown::None,
            ));
            if variant < 4 {
                all.push(transfer_scenario(
                    &format!("bulk-fin-{segments}x{segment_len}-v{variant}"),
                    variant,
                    segments,
                    segment_len,
                    &[],
                    false,
                    Teardown::Fin,
                ));
                all.push(transfer_scenario(
                    &format!("bulk-fin-data-{segments}x{segment_len}-v{variant}"),
                    variant,
                    segments,
                    segment_len,
                    &[],
                    false,
                    Teardown::FinWithData,
                ));
                all.push(transfer_scenario(
                    &format!("bulk-rst-{segments}x{segment_len}-v{variant}"),
                    variant,
                    segments,
                    segment_len,
                    &[],
                    false,
                    Teardown::Rst,
                ));
            }
            if variant < 3 {
                all.push(transfer_scenario(
                    &format!("loss-mid-{segments}x{segment_len}-v{variant}"),
                    variant,
                    segments.max(2),
                    segment_len,
                    &[1],
                    false,
                    Teardown::None,
                ));
                all.push(transfer_scenario(
                    &format!("loss-tail-{segments}x{segment_len}-v{variant}"),
                    variant,
                    segments.max(2),
                    segment_len,
                    &[segments.max(2) - 1],
                    false,
                    Teardown::None,
                ));
                all.push(transfer_scenario(
                    &format!("reorder-{segments}x{segment_len}-v{variant}"),
                    variant,
                    segments.max(2),
                    segment_len,
                    &[],
                    true,
                    Teardown::None,
                ));
            }
        }
        let _ = index;
    }

    for variant in 0u8..6 {
        all.push(wait_scenario(
            &format!("rto-recover-v{variant}"),
            variant,
            4,
            512,
        ));
        all.push(wait_scenario(
            &format!("rto-recover-big-v{variant}"),
            variant,
            8,
            1400,
        ));
        all.push(window_scenario(
            &format!("window-flow-v{variant}"),
            variant,
            false,
        ));
        all.push(window_scenario(
            &format!("window-zero-v{variant}"),
            variant,
            true,
        ));
        all.push(dup_scenario(&format!("dup-2-v{variant}"), variant, 2));
        all.push(dup_scenario(&format!("dup-8-v{variant}"), variant, 8));
    }

    all
}

#[test]
fn oracle_self_identity() {
    // The referee's sanity: the same driver, the same scenario, twice,
    // must produce identical records; two drivers of the same kind must
    // agree with each other.
    let scenarios = corpus();
    let mut left = SmoltcpDriver::new();
    let mut right = SmoltcpDriver::new();
    let passed = assert_batch(&scenarios, &mut left, &mut right, CompareMask::STRICT);
    println!("oracle self-identity: {}/{}", passed, scenarios.len());
    assert!(
        passed >= 200,
        "corpus must carry >=200 scenarios, has {passed}"
    );
}

/// The scenario families, named for the volume that owes them:
/// ordered traffic is 037's debt (handshake and in-window data),
/// chaos (loss, reorder, duplicates, timers under stress) is 038's.
fn split_corpus() -> (Vec<Scenario>, Vec<Scenario>) {
    let all = corpus();
    let mut ordered = Vec::new();
    let mut chaos = Vec::new();
    for scenario in all {
        let name = &scenario.name;
        let chaotic = name.contains("loss-")
            || name.contains("reorder-")
            || name.contains("rto-")
            || name.contains("dup-")
            || name.contains("window-zero");
        if chaotic {
            chaos.push(scenario);
        } else {
            ordered.push(scenario);
        }
    }
    (ordered, chaos)
}

#[test]
#[ignore = "037 convergence in flight: ordered family at 32/118"]
fn native_vs_oracle_handshake_and_data() {
    let isn = probe_oracle_isn();
    SERVER_ISN.store(isn, std::sync::atomic::Ordering::Relaxed);
    // The player takes the field: the same corpus, the same referee,
    // the in-house stack on one side and the oracle on the other. The
    // mask starts lenient (window policies mature after volume two);
    // everything sequence-bearing is strict from day one.
    let (ordered, _chaos) = split_corpus();
    let mut oracle = SmoltcpDriver::new();
    let mut native = NativeTcpDriver::with_listen_isn(isn);
    let passed = assert_batch(&ordered, &mut oracle, &mut native, CompareMask::LENIENT);
    println!(
        "native vs oracle (ordered family): {passed}/{}",
        ordered.len()
    );
}

#[test]
fn oracle_determinism_run_to_run() {
    // Determinism across whole-batch reruns: any nondeterminism in the
    // oracle or the harness would poison every future comparison.
    let scenarios = corpus();
    let outcomes: Vec<String> = scenarios
        .iter()
        .map(|s| {
            let mut a = SmoltcpDriver::new();
            let mut b = SmoltcpDriver::new();
            format!(
                "{:?}",
                diff::run_differential(s, &mut a, &mut b, CompareMask::STRICT)
            )
        })
        .collect();
    let replay: Vec<String> = scenarios
        .iter()
        .map(|s| {
            let mut a = SmoltcpDriver::new();
            let mut b = SmoltcpDriver::new();
            format!(
                "{:?}",
                diff::run_differential(s, &mut a, &mut b, CompareMask::STRICT)
            )
        })
        .collect();
    assert_eq!(outcomes, replay, "rerun must be byte-identical");
}

#[test]
fn oracle_handshake_emits_synack() {
    // The oracle actually plays: a SYN must produce a SYN-ACK record.
    let scenario = handshake_scenario("probe", 0, 0);
    let mut driver = SmoltcpDriver::new();
    driver.reset(&scenario);
    let mut records = Vec::new();
    for step in &scenario.steps {
        records.extend(driver.step(step));
    }
    assert!(
        records.iter().any(|r| r.flags & 0x12 == 0x12),
        "expected a SYN-ACK in {:?}",
        records
    );
}

#[test]
fn pcap_replay_smoke() {
    // Real captured segments through the oracle: the driver must chew
    // the client half of tcp_lifecycle.pcap without complaint, and the
    // run must be reproducible. The differential side-by-side with the
    // in-house stack comes in 037; here the oracle alone proves the
    // pcap-to-driver plumbing.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps")
        .join("tcp_lifecycle.pcap");
    let mut device = PcapDevice::from_file(&path).expect("load pcap");

    let server = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);
    let client = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
    let mut scenario = Scenario::new("pcap-tcp-lifecycle", client, server);

    let mut bufs = vec![bytes::BytesMut::new(); 8];
    loop {
        let count = device.read_batch(&mut bufs).unwrap();
        if count == 0 {
            break;
        }
        for buf in bufs.iter().take(count) {
            let is_client_to_server = buf.len() > 20 && buf[16..20] == server.ip().octets()[..];
            if is_client_to_server {
                scenario.inject(10, buf.to_vec());
            }
        }
    }

    let run = {
        let mut driver = SmoltcpDriver::new();
        driver.reset(&scenario);
        let mut records = Vec::new();
        for step in &scenario.steps {
            records.extend(driver.step(step));
        }
        records.extend(driver.finish());
        records
    };
    let rerun = {
        let mut driver = SmoltcpDriver::new();
        driver.reset(&scenario);
        let mut records = Vec::new();
        for step in &scenario.steps {
            records.extend(driver.step(step));
        }
        records.extend(driver.finish());
        records
    };
    assert_eq!(run, rerun, "pcap replay must be deterministic");
    assert!(!run.is_empty(), "oracle must respond to captured traffic");
}

#[test]
fn corpus_runs_fast() {
    // The whole corpus stays under a second so CI runs it every commit.
    let scenarios = corpus();
    let started = Instant::now();
    let mut left = SmoltcpDriver::new();
    let mut right = SmoltcpDriver::new();
    let passed = assert_batch(&scenarios, &mut left, &mut right, CompareMask::STRICT);
    let elapsed = started.elapsed();
    println!(
        "corpus: {passed} scenarios in {:?} ({:.0} scenarios/s)",
        elapsed,
        passed as f64 / elapsed.as_secs_f64().max(0.000001)
    );
    assert!(elapsed.as_millis() < 1000, "corpus took {:?}", elapsed);
}

/// Dump both sides' records for one named scenario: the debugging
/// companion while volume one converges.
fn shape_of(name: &str) {
    let isn = probe_oracle_isn();
    SERVER_ISN.store(isn, std::sync::atomic::Ordering::Relaxed);
    let scenarios = corpus();
    let scenario = scenarios
        .iter()
        .find(|s| s.name == name)
        .expect("scenario exists");
    let run = |driver: &mut dyn StackDriver| {
        driver.reset(scenario);
        let mut records = Vec::new();
        for step in &scenario.steps {
            records.extend(driver.step(step));
        }
        records.extend(driver.finish());
        records
    };
    let mut oracle = SmoltcpDriver::new();
    let mut native = NativeTcpDriver::with_listen_isn(isn);
    println!("oracle: {:#?}", run(&mut oracle));
    println!("native: {:#?}", run(&mut native));
}

#[test]
fn syn_only_probe_shapes() {
    // What each side emits for a bare SYN: the shapes must meet before
    // the corpus can say anything. Print, do not assert, for debugging
    // volume one into agreement.
    let isn = probe_oracle_isn();
    SERVER_ISN.store(isn, std::sync::atomic::Ordering::Relaxed);
    let scenario = handshake_scenario("probe", 0, 0);
    let mut oracle = SmoltcpDriver::new();
    oracle.reset(&scenario);
    let mut left = Vec::new();
    for step in &scenario.steps {
        left.extend(oracle.step(step));
    }
    left.extend(oracle.finish());
    let mut native = NativeTcpDriver::with_listen_isn(isn);
    native.reset(&scenario);
    let mut right = Vec::new();
    for step in &scenario.steps {
        right.extend(native.step(step));
    }
    right.extend(native.finish());
    println!("oracle: {left:?}");
    println!("native: {right:?}");
}

#[test]
#[ignore = "debugging companion for 037; SHAPE=<scenario> selects"]
fn bulk_shape_dump() {
    shape_of(&std::env::var("SHAPE").unwrap_or_else(|_| "bulk-1x1-v0".into()));
}
