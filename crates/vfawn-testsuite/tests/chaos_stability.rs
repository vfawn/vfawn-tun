// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Chaos stability: the same scripted client, but the delivery layer
//! drops, duplicates, and reorders packets on a fixed seed. The bar is
//! survival: no panic, no hang, and the session still delivers every
//! byte exactly once: sequence-space bookkeeping must deduplicate
//! whatever the channel did. Record equality under clean delivery is
//! the differential corpus's job; hostile sequencing is this one's.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use vfawn_core::{
    DeviceCaps, FlowInfo, PacketDevice, SessionHandler, StackBackend, TcpSession, Verdict,
};
use vfawn_stack_user::NativeBackend;
use vfawn_testsuite::{MockDevice, Script};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 45678);
const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);

/// A tiny deterministic PRNG (an LCG): fixed seed, fixed sequence, so a
/// failure here reproduces bit for bit.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

/// How the channel mangles one batch: roughly five percent dropped,
/// five percent duplicated, and adjacent swaps through the batch. All
/// decisions derive from the seeded sequence alone.
fn mangle(packets: &mut Vec<bytes::BytesMut>, rng: &mut Lcg) {
    let mut kept: Vec<bytes::BytesMut> = Vec::with_capacity(packets.len() * 2);
    for packet in packets.iter() {
        let roll = rng.next() % 100;
        if roll < 5 {
            continue; // dropped: retransmission must recover this
        }
        kept.push(packet.clone());
        if roll < 10 {
            kept.push(packet.clone()); // duplicated: dedup must absorb
        }
    }
    // Adjacent pairwise swaps on a second roll for real reordering.
    let mut index = 1;
    while index < kept.len() {
        let roll = rng.next() % 100;
        if roll < 25 {
            kept.swap(index - 1, index);
            index += 2;
        } else {
            index += 1;
        }
    }
    *packets = kept;
}

/// Delivers the mangled stream over whatever device it wraps.
struct ChaoticDevice {
    inner: Box<dyn PacketDevice>,
    rng: std::sync::Mutex<Lcg>,
}

impl PacketDevice for ChaoticDevice {
    fn read_batch(&mut self, bufs: &mut [bytes::BytesMut]) -> std::io::Result<usize> {
        let mut staged: Vec<bytes::BytesMut> = Vec::new();
        loop {
            let count = self.inner.read_batch(bufs)?;
            if count == 0 {
                break;
            }
            for buf in bufs.iter_mut().take(count) {
                staged.push(std::mem::take(buf));
            }
        }
        if staged.is_empty() {
            return Ok(0);
        }
        mangle(&mut staged, &mut self.rng.lock().expect("rng lock"));
        let delivered = staged.len().min(bufs.len());
        for (slot, packet) in bufs.iter_mut().zip(staged.into_iter()) {
            *slot = packet;
        }
        Ok(delivered)
    }

    fn write_batch(&mut self, bufs: &[bytes::BytesMut]) -> std::io::Result<usize> {
        self.inner.write_batch(bufs)
    }

    fn capabilities(&self) -> DeviceCaps {
        self.inner.capabilities()
    }

    fn shutdown(&self) -> std::io::Result<()> {
        self.inner.shutdown()
    }

    fn duplicate(&self) -> std::io::Result<Box<dyn PacketDevice>> {
        // Shares the wrapped device's queues (MockDevice duplicates
        // share), so the test's pushes reach the backend's reader and
        // the stack's writes reach the test's inspection list.
        Ok(Box::new(ChaoticDevice {
            inner: self.inner.duplicate()?,
            rng: std::sync::Mutex::new(Lcg(0x5eed)),
        }))
    }
}

struct CountingEcho {
    sessions: AtomicUsize,
    bytes_in: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionHandler for CountingEcho {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 4096];
        while let Ok(n) = session.read(&mut buf).await
            && n > 0
        {
            self.bytes_in.fetch_add(n, Ordering::SeqCst);
            let peer = session.flow().source;
            let _ = session.write(&buf[..n]).await;
            let _ = peer;
        }
        let _ = session.shutdown_write().await;
    }

    async fn on_udp(&self, _session: vfawn_core::UdpSession) {}

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

fn wait_for<F: FnMut() -> bool>(mut predicate: F, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn chaotic_delivery_survives_and_delivers_exactly_once() {
    let handler = Arc::new(CountingEcho {
        sessions: AtomicUsize::new(0),
        bytes_in: AtomicUsize::new(0),
    });

    // The mock is the shared channel; the chaotic wrapper only mangles
    // the read direction on its way into the stack.
    let mock = MockDevice::new(DeviceCaps::MINIMAL);
    let chaotic = ChaoticDevice {
        inner: mock.duplicate().unwrap(),
        rng: std::sync::Mutex::new(Lcg(0x5eed)),
    };
    let backend = Box::new(NativeBackend::default());
    let _handle = backend
        .spawn(Box::new(chaotic), handler.clone())
        .expect("spawn native backend");

    let script = Script::new(CLIENT, SERVER);
    let payload: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();

    // Handshake first, cleanly enough to find the server's sequence.
    // A real peer retransmits its SYN; three copies ride out any
    // single drop the channel rolls.
    for _ in 0..3 {
        mock.push(&[&script.tcp(1000, 0, 0x02, b"")]);
        std::thread::sleep(Duration::from_millis(30));
    }
    let mut synack = None;
    wait_for(
        || {
            let written = mock.take_written();
            synack = written
                .into_iter()
                .find(|p| p.len() >= 40 && p[9] == 6 && p[33] & 0x12 == 0x12);
            synack.is_some()
        },
        "SYN-ACK",
    );
    let synack = synack.expect("SYN-ACK");
    let server_seq = u32::from_be_bytes([synack[24], synack[25], synack[26], synack[27]]);
    mock.push(&[&script.tcp(1001, server_seq.wrapping_add(1), 0x10, b"")]);

    // Data under chaos. Retransmissions are the client's side of the
    // bargain: anything the mangler dropped comes again after a pause,
    // exactly like a real peer's RTO.
    let chunk = 512;
    for index in 0..payload.len() / chunk {
        let start = index * chunk;
        mock.push(&[&script.tcp(
            (1001 + start) as u32,
            server_seq.wrapping_add(1),
            0x18,
            &payload[start..start + chunk],
        )]);
        std::thread::sleep(Duration::from_millis(20));
    }
    // A full retransmission pass: chaos likely ate something.
    for index in 0..payload.len() / chunk {
        let start = index * chunk;
        mock.push(&[&script.tcp(
            (1001 + start) as u32,
            server_seq.wrapping_add(1),
            0x10,
            &payload[start..start + chunk],
        )]);
        std::thread::sleep(Duration::from_millis(20));
    }

    wait_for(
        || handler.bytes_in.load(Ordering::SeqCst) >= payload.len(),
        "every byte delivered",
    );
    assert_eq!(
        handler.bytes_in.load(Ordering::SeqCst),
        payload.len(),
        "duplicates must deduplicate to the original count"
    );
    assert_eq!(handler.sessions.load(Ordering::SeqCst), 1);
}
