// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The darwin batch path against a live kernel: real routed traffic
//! in, batch sizes out, one bounced frame back. Run under root
//! (the runner provides passwordless sudo):
//!
//! ```text
//! sudo -E cargo test -p vfawn-device --test darwin_batch -- --ignored --nocapture
//! ```

#![cfg(target_os = "macos")]

use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use vfawn_core::{DeviceConfig, PacketDevice};
use vfawn_device::TunDevice;

/// The interface's own prefix and the prefix routed into it.
const IFACE_NET: &str = "198.18.0.1/24";
const ROUTED_NET: &str = "198.18.1.0/24";
const PROBE_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 1, 7);
const PROBE_PORT: u16 = 5353;
const PROBES: usize = 400;

/// What the batch evidence says: packets per batch read, which is the
/// syscall count per packet turned upside down.
#[test]
#[ignore]
fn batch_reads_and_the_writev_round_trip() {
    // Root hands us the address; the route is the system's own tool.
    assert_root();
    let device = TunDevice::create(&DeviceConfig {
        mtu: 1500,
        inet4_address: vec![IFACE_NET.parse().expect("interface prefix")],
        ..DeviceConfig::default()
    })
    .expect("device");
    let name = device.name().expect("name");
    route_add(&name);

    // A connected probe socket with a wide send buffer: every datagram
    // leaves the process before the first read, so the kernel — not a
    // racing reader — decides the batching.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
    let sndbuf: libc::c_int = 1 << 20;
    // SAFETY: a plain integer socket option on a descriptor this
    // process owns.
    #[expect(unsafe_code)]
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sndbuf as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    socket
        .connect(std::net::SocketAddr::from((PROBE_ADDR, PROBE_PORT)))
        .expect("connect");
    let payload_body = |n: usize| format!("vfawn-batch-probe-{n:04}");
    for n in 0..PROBES {
        socket
            .send_to(
                payload_body(n).as_bytes(),
                std::net::SocketAddr::from((PROBE_ADDR, PROBE_PORT)),
            )
            .expect("send");
    }

    // Read everything back in caller-sized slices, exactly as the
    // pipeline does, and count batch messages against frames.
    let mut device = device;
    let mut bufs = vec![BytesMut::new(); 8];
    let mut batches = 0usize;
    let mut frames = 0usize;
    let mut first: Option<Vec<u8>> = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while frames < PROBES && Instant::now() < deadline {
        let count = device.read_batch(&mut bufs).expect("read");
        if count == 0 {
            continue;
        }
        batches += 1;
        for buf in bufs.iter_mut().take(count) {
            if first.is_none() {
                first = Some(buf.to_vec());
            }
            frames += 1;
        }
    }
    assert_eq!(frames, PROBES, "every probe reached the reader");
    let per_batch = frames as f64 / batches as f64;
    println!(
        "batch evidence: {frames} packets in {batches} reads = {per_batch:.1} packets/read; \
         per-packet would be 1.0 ({batches} vs {frames} syscalls)"
    );
    assert!(
        per_batch >= 4.0,
        "steady-state batching must clear four packets per read, saw {per_batch:.1}"
    );

    // The write path: bounce one frame back — endpoints swapped, the
    // header checksum recomputed, the datagram checksum elided (a
    // zero is legal in IPv4) — and the probe socket must see it.
    let inbound = first.expect("a frame was read");
    let reply = bounce(&inbound).expect("a UDP frame to bounce");
    let mut one = [BytesMut::from(&reply[..])];
    assert_eq!(device.write_batch(&mut one).expect("write"), 1);
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let mut seen = [0u8; 64];
    let n = socket.recv(&mut seen).expect("bounced datagram");
    let seen_text = String::from_utf8_lossy(&seen[..n]).to_string();
    assert!(
        seen_text.starts_with("vfawn-batch-probe-"),
        "the bounce carried the probe payload: {seen_text}"
    );

    route_del(&name);
    device.shutdown().expect("shutdown");
}

/// Swap the endpoints of one IPv4+UDP frame and fix its header
/// checksum. The datagram checksum is set to zero — legal and
/// unchecked in IPv4.
fn bounce(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 20 + 8 || frame[0] >> 4 != 4 {
        return None;
    }
    let ihl = (frame[0] as usize & 0x0f) * 4;
    if frame.len() < ihl + 8 {
        return None;
    }
    let mut reply = frame.to_vec();
    for index in 0..4 {
        reply.swap(12 + index, 16 + index);
    }
    let src_port = u16::from_be_bytes([reply[ihl], reply[ihl + 1]]);
    let dst_port = u16::from_be_bytes([reply[ihl + 2], reply[ihl + 3]]);
    reply[ihl..ihl + 2].copy_from_slice(&dst_port.to_be_bytes());
    reply[ihl + 2..ihl + 4].copy_from_slice(&src_port.to_be_bytes());
    reply[ihl + 6..ihl + 8].copy_from_slice(&[0, 0]);
    reply[10..12].copy_from_slice(&[0, 0]);
    let checksum = ip_checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&checksum.to_be_bytes());
    Some(reply)
}

/// The one's-complement sum of the header's 16-bit words.
fn ip_checksum(header: &[u8]) -> u16 {
    let sum: u32 = header
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u16::from_be_bytes(*word) as u32)
        .sum();
    !(sum + (sum >> 16)) as u16
}

fn route_add(name: &str) {
    let status = Command::new("route")
        .args(["-n", "add", "-net", ROUTED_NET, "-interface", name])
        .output()
        .expect("route command");
    assert!(
        status.status.success(),
        "route add failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

fn route_del(name: &str) {
    let _ = Command::new("route")
        .args(["-n", "delete", "-net", ROUTED_NET, "-interface", name])
        .output();
}

fn assert_root() {
    // SAFETY: geteuid has no preconditions.
    #[expect(unsafe_code)]
    let euid = unsafe { libc::geteuid() };
    assert_eq!(euid, 0, "this test routes real traffic; it needs root");
}
