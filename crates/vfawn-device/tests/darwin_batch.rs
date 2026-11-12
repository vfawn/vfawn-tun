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

/// The interface's own address and the on-link neighbor the probes
/// aim at, one island per round: the address installs with a /24
/// whatever the config's prefix says, so the probe neighbor lives
/// inside that /24. The islands never repeat — two live interfaces
/// claiming one subnet leave the connected route's winner to the
/// kernel's interface ordering, which a pool's kernel generation
/// changed under this test once: every probe silently routed to the
/// other (already dying) island and the fresh interface read zero
/// with its routes and addresses all present.
fn island(round: u32) -> (String, Ipv4Addr, Ipv4Addr) {
    let octet = 40 + round as u8;
    (
        format!("198.18.{octet}.1/24"),
        Ipv4Addr::new(198, 18, octet, 1),
        Ipv4Addr::new(198, 18, octet, 7),
    )
}
const PROBE_PORT: u16 = 5353;
const PROBES: usize = 400;

/// One full exchange on one device: send every probe, read them
/// back, and report (frames, batches).
fn probe_round(device: &mut TunDevice) -> (usize, usize) {
    let mut bufs = vec![BytesMut::new(); 8];
    let mut batches = 0usize;
    let mut frames = 0usize;
    let deadline = Instant::now() + Duration::from_secs(6);
    while frames < PROBES && Instant::now() < deadline {
        let count = device.read_batch(&mut bufs).expect("read");
        if count == 0 {
            continue;
        }
        batches += 1;
        for buf in bufs.iter_mut().take(count) {
            // Only the probes count: a routed interface also carries
            // the kernel's own housekeeping, which is not probe loss.
            // The payload begins at twenty-eight: the IP header's
            // twenty plus the UDP header's eight. An earlier matcher
            // looked at forty and never matched a probe — the
            // "zero-read" the pool change was blamed for was this
            // line all along.
            if is_probe(buf, b"vfawn-batch-probe-") {
                frames += 1;
            }
        }
    }
    (frames, batches)
}

/// A UDP frame whose payload opens with `tag`. The payload begins at
/// twenty-eight: the IP header's twenty plus the UDP header's eight.
fn is_probe(frame: &[u8], tag: &[u8]) -> bool {
    frame.len() > 28 && frame[9] == 17 && frame[28..].starts_with(tag)
}

/// What the batch evidence says: packets per batch read, which is the
/// syscall count per packet turned upside down.
#[test]
#[ignore]
fn batch_reads_and_the_writev_round_trip() {
    // Root hands us the address; the route is the system's own tool.
    assert_root();

    let mut round = 0;
    let (frames, batches) = loop {
        round += 1;
        let (net, iface_addr, probe_addr) = island(round);
        let mut device = TunDevice::create(&DeviceConfig {
            mtu: 1500,
            inet4_address: vec![net.parse().expect("interface prefix")],
            ..DeviceConfig::default()
        })
        .expect("device");
        // The kernel's own answer to which interface the probes will
        // enter: printed before any read, so a zero-read round leaves
        // the routing truth beside it.
        let picked = Command::new("route")
            .args(["-n", "get", &probe_addr.to_string()])
            .output();
        if let Ok(output) = picked {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if line.contains("interface:") {
                    println!("round {round}: {line}");
                }
            }
        }
        // A connected probe socket with a wide send buffer: every datagram
        // leaves the process before the first read, so the kernel — not a
        // racing reader — decides the batching. The own-address bind also
        // decides the bounce: a reply destined to the interface's address
        // passes the kernel's interface check.
        let socket =
            std::net::UdpSocket::bind(std::net::SocketAddr::from((iface_addr, 0))).expect("bind");
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
            .connect(std::net::SocketAddr::from((probe_addr, PROBE_PORT)))
            .expect("connect");

        let payload_body = |n: usize| format!("vfawn-batch-probe-{n:04}");
        for n in 0..PROBES {
            socket.send(payload_body(n).as_bytes()).expect("send");
        }
        let outcome = probe_round(&mut device);
        let _ = device.shutdown();
        if outcome.0 > 0 || round >= 3 {
            break outcome;
        }
        println!("round {round} read zero; retrying on a fresh island");
    };
    if frames == 0 {
        // The diagnosis the zero deserves: where the routes point and
        // which interfaces live.
        let routes = Command::new("netstat").args(["-rn", "-f", "inet"]).output();
        if let Ok(output) = routes {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if line.contains("198.18") || line.contains("utun") {
                    println!("route: {line}");
                }
            }
        }
        panic!("every probe reached the reader (saw zero in both rounds; diagnostics above)");
    }
    assert_eq!(frames, PROBES, "every probe reached the reader");
    let per_batch = frames as f64 / batches as f64;
    println!(
        "batch evidence: {frames} packets in {batches} reads = {per_batch:.1} packets/read; \
         per-packet would be 1.0 ({batches} vs {frames} syscalls)"
    );
    // The loop exits the moment the last probe lands, cutting its
    // batch short; the floor asks only that batching exist at all —
    // two packets per read already halves the syscall count the
    // per-packet path would pay.
    assert!(
        per_batch >= 2.0,
        "batching must at least halve the per-packet syscall count, saw {per_batch:.1}"
    );

    // The write path needs a live device again: the probe rounds tore
    // theirs down. The receipt is delivery, not the interface's input
    // counter: that counter ticks before the kernel's protocol demux
    // reads the family prefix, so a prefix in the wrong byte order
    // passed it while every written frame died in the demux.
    let (net, iface_addr, probe_addr) = island(9);
    let mut device = TunDevice::create(&DeviceConfig {
        mtu: 1500,
        inet4_address: vec![net.parse().expect("interface prefix")],
        ..DeviceConfig::default()
    })
    .expect("write-path device");
    const BOUNCE_PROBE: &[u8] = b"vfawn-bounce-probe";
    let socket =
        std::net::UdpSocket::bind(std::net::SocketAddr::from((iface_addr, 0))).expect("bind");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    socket
        .connect(std::net::SocketAddr::from((probe_addr, PROBE_PORT)))
        .expect("connect");
    socket.send(BOUNCE_PROBE).expect("send");

    let mut bufs = vec![BytesMut::new(); 8];
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut inbound = None;
    while inbound.is_none() && Instant::now() < deadline {
        let count = device.read_batch(&mut bufs).expect("read");
        inbound = bufs
            .iter()
            .take(count)
            .find(|buf| is_probe(buf, BOUNCE_PROBE))
            .map(|buf| buf.to_vec());
    }
    let inbound = inbound.expect("the bounce probe reached the reader");
    let reply = bounce(&inbound).expect("a UDP frame to bounce");
    let mut one = [BytesMut::from(&reply[..])];
    assert_eq!(device.write_batch(&mut one).expect("write"), 1);

    // The connected socket takes only its peer's datagrams: the
    // bounce, sourced from the probe address and port, is exactly one.
    let mut answer = [0u8; 64];
    let received = socket
        .recv(&mut answer)
        .expect("the written frame must reach the socket it was bounced to");
    assert_eq!(&answer[..received], BOUNCE_PROBE);

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

fn assert_root() {
    // SAFETY: geteuid has no preconditions.
    #[expect(unsafe_code)]
    let euid = unsafe { libc::geteuid() };
    assert_eq!(euid, 0, "this test routes real traffic; it needs root");
}

/// The host-supplied descriptor path: a utun created by the host's own
/// tooling is adopted by fd, and reads flow. This is the network
/// extension's shape — the interface exists before this process does.
#[test]
#[ignore]
fn a_host_fd_is_adopted_and_reads() {
    assert_root();
    // Its own address island: the sibling exchange owns 198.18.0.x.
    const ADOPTED_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 2, 1);
    const ADOPTED_PROBE: Ipv4Addr = Ipv4Addr::new(198, 18, 2, 7);

    // Create with the host's tooling — address included, as a host
    // that built the interface would have — then hand over a
    // duplicate of the fd: the original wrapper drops and closes its
    // side, the dup keeps the interface alive with exactly one owner,
    // the adoption.
    let owned = tun_rs::DeviceBuilder::new()
        .mtu(1500)
        .ipv4(ADOPTED_ADDR, 24, None)
        .build_sync()
        .expect("host utun");
    // SAFETY: dup of a live descriptor this test owns.
    #[expect(unsafe_code)]
    let fd = unsafe { libc::dup(owned.as_raw_fd()) };
    drop(owned);
    // SAFETY: the fd above is a live utun descriptor this test just
    // created and whose only owner is now the adoption.
    #[expect(unsafe_code)]
    let mut device = unsafe { TunDevice::from_fd(fd) }.expect("adopt");

    let socket =
        std::net::UdpSocket::bind(std::net::SocketAddr::from((ADOPTED_ADDR, 0))).expect("bind");
    socket
        .connect(std::net::SocketAddr::from((ADOPTED_PROBE, PROBE_PORT)))
        .expect("connect");
    for _ in 0..8 {
        socket.send(b"adopted-fd-probe").expect("send");
    }

    let mut bufs = vec![BytesMut::new(); 8];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = 0;
    while seen == 0 && Instant::now() < deadline {
        let count = device.read_batch(&mut bufs).expect("read");
        seen += count;
    }
    assert!(seen > 0, "the adopted fd reads the probes");
    device.shutdown().expect("shutdown");
}
