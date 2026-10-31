// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The anti-loop demo, asserted with delivered packets rather than eyes.
//!
//! One namespace, two veth pairs, one TUN. A policy rule captures every
//! destination into the TUN the way a real capture setup does. Then:
//!
//! * an ordinary socket's datagram to a far address lands in the TUN
//!   queue, read straight off the device fd (the loop, control group);
//! * a socket the hook bound to the first veth delivers a datagram to a
//!   listener on that veth's peer address;
//! * after the default route moves to the second veth, a freshly
//!   protected socket delivers through the new one, while the old
//!   socket keeps its old binding (snapshots do not migrate).
//!
//! Delivery is proven by a receiving socket, which is stronger than a
//! capture: the kernel only hands a datagram to a listener when the
//! packet truly traversed the veth. The test re-executes itself inside
//! the namespace, so the body runs our real `protect` chain against the
//! namespace's routing table.
//!
//! ```sh
//! sudo -E cargo test -p vfawn-platform --test anti_loop_netns -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use vfawn_core::OutboundFdHook;
use vfawn_platform::linux::protect;

const NS: &str = "vfawn023";
const FAR: &str = "203.0.113.10:9";
const MARKER: &str = "203.0.113.10";
const LISTEN_PORT: u16 = 9999;

fn run(mut cmd: Command) {
    let output = cmd.output().expect("spawn command");
    if !output.status.success() {
        panic!(
            "command failed: {:?}\n{}{}",
            cmd,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

fn ip(args: &[&str]) -> Command {
    let mut c = Command::new("ip");
    c.args(args);
    c
}

fn in_ns(args: &[&str]) -> Command {
    let mut c = Command::new("ip");
    c.arg("netns").arg("exec").arg(NS).args(args);
    c
}

fn in_body() -> bool {
    std::env::var("VFAWN_ANTILOOP_BODY").is_ok()
}

/// A listener thread on one veth peer, counting datagrams the namespace
/// sends its way.
fn spawn_listener(address: &str) -> Arc<AtomicUsize> {
    let socket = UdpSocket::bind(format!("{address}:{LISTEN_PORT}"))
        .unwrap_or_else(|e| panic!("bind listener on {address}: {e}"));
    socket
        .set_read_timeout(Some(Duration::from_secs(6)))
        .expect("listener timeout");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    std::thread::Builder::new()
        .name(format!("listener-{address}"))
        .spawn(move || {
            let mut buf = [0u8; 64];
            while let Ok(n) = socket.recv(&mut buf) {
                if n == 0 {
                    break;
                }
                counter.fetch_add(1, Ordering::SeqCst);
            }
        })
        .expect("spawn listener");
    hits
}

#[test]
#[ignore]
fn policy_capture_loops_and_bound_sockets_escape() {
    if in_body() {
        body();
        return;
    }

    // Leftovers from a crashed run must not wedge the setup.
    let _ = ip(&["netns", "del", NS]).output();
    let _ = ip(&["link", "del", "v0b"]).output();
    let _ = ip(&["link", "del", "v1b"]).output();

    run(ip(&["netns", "add", NS]));
    // The TUN queue must carry only the traffic under test; IPv6 link
    // management would add noise. The default template covers every
    // interface created after this line.
    run(in_ns(&[
        "sysctl",
        "-q",
        "-w",
        "net.ipv6.conf.default.disable_ipv6=1",
    ]));
    run(ip(&[
        "link", "add", "v0a", "type", "veth", "peer", "name", "v0b",
    ]));
    run(ip(&[
        "link", "add", "v1a", "type", "veth", "peer", "name", "v1b",
    ]));
    run(ip(&["link", "set", "v0a", "netns", NS]));
    run(ip(&["link", "set", "v1a", "netns", NS]));
    run(ip(&["addr", "add", "10.200.0.2/24", "dev", "v0b"]));
    run(ip(&["link", "set", "v0b", "up"]));
    run(ip(&["addr", "add", "10.201.0.2/24", "dev", "v1b"]));
    run(ip(&["link", "set", "v1b", "up"]));
    run(in_ns(&["ip", "link", "set", "lo", "up"]));
    run(in_ns(&["ip", "addr", "add", "10.200.0.1/24", "dev", "v0a"]));
    run(in_ns(&["ip", "link", "set", "v0a", "up"]));
    run(in_ns(&["ip", "addr", "add", "10.201.0.1/24", "dev", "v1a"]));
    run(in_ns(&["ip", "link", "set", "v1a", "up"]));
    run(in_ns(&[
        "ip", "tuntap", "add", "dev", "tun0", "mode", "tun",
    ]));
    run(in_ns(&["ip", "link", "set", "dev", "tun0", "up"]));
    run(in_ns(&[
        "ip",
        "addr",
        "add",
        "198.18.0.1/32",
        "dev",
        "tun0",
    ]));
    // Main-table default through the first veth; the capture rule sits
    // above it and pulls everything into the TUN.
    run(in_ns(&[
        "ip",
        "route",
        "add",
        "default",
        "via",
        "10.200.0.2",
        "dev",
        "v0a",
    ]));
    run(in_ns(&[
        "ip", "route", "add", "table", "100", "default", "dev", "tun0",
    ]));
    run(in_ns(&[
        "ip", "rule", "add", "pref", "100", "lookup", "100",
    ]));

    // Control: with no binding, the far destination routes into the TUN.
    let control = in_ns(&["ip", "route", "get", MARKER])
        .output()
        .expect("route get");
    let text = String::from_utf8_lossy(&control.stdout).to_string();
    assert!(
        text.contains("dev tun0"),
        "control must route into the TUN, got: {text}"
    );

    // Listeners on both peer addresses, running while the body sends.
    let v0_listener = spawn_listener("10.200.0.2");
    let v1_listener = spawn_listener("10.201.0.2");

    // Re-run this very test inside the namespace.
    let exe = std::env::current_exe()
        .expect("test binary path")
        .to_string_lossy()
        .into_owned();
    let body = in_ns(&[&exe])
        .arg("policy_capture_loops_and_bound_sockets_escape")
        .arg("--ignored")
        .arg("--exact")
        .arg("--nocapture")
        .env("VFAWN_ANTILOOP_BODY", "1")
        .output()
        .expect("run body in namespace");
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(&body.stderr);
    assert!(
        body.status.success(),
        "namespace body failed (see stderr above)"
    );

    // Give late datagrams a moment before counting.
    std::thread::sleep(Duration::from_secs(1));
    run(ip(&["netns", "del", NS]));

    let through_v0 = v0_listener.load(Ordering::SeqCst);
    let through_v1 = v1_listener.load(Ordering::SeqCst);
    assert!(
        through_v0 >= 1,
        "the protected socket escaped through v0 ({through_v0} datagrams delivered)"
    );
    assert!(
        through_v1 >= 1,
        "after the flip, a fresh socket escaped through v1 ({through_v1} datagrams delivered)"
    );
}

/// What runs inside the namespace: real sockets, real `protect` calls.
fn body() {
    // Attach the TUN before anything sends: a tun with no reader drops
    // packets on the floor, and the loop must be observed, not assumed.
    let tun = attach_tun("tun0");

    // 1. The loop: an ordinary socket, captured by the rule.
    let plain = UdpSocket::bind("0.0.0.0:0").expect("plain socket");
    plain
        .send_to(b"loop", FAR)
        .expect("send is accepted into the TUN");

    // 2. The escape: protect resolves the default interface (v0a here)
    // and binds the socket to it. Delivery to the peer address is the
    // listener's to observe outside; a few probes pay for ARP.
    let guarded = UdpSocket::bind("0.0.0.0:0").expect("guarded socket");
    let bound = protect(&OutboundFdHook::BindDefaultIface, guarded.as_raw_fd())
        .expect("protect the socket");
    assert_eq!(bound.as_deref(), Some("v0a"));
    let escape_target = format!("10.200.0.2:{LISTEN_PORT}");
    for _ in 0..3 {
        guarded
            .send_to(b"escape", &escape_target)
            .expect("send escapes via v0a");
        std::thread::sleep(Duration::from_millis(100));
    }

    // 3. The network changes: default route moves to the second veth.
    run(ip(&[
        "route",
        "replace",
        "default",
        "via",
        "10.201.0.2",
        "dev",
        "v1a",
    ]));

    // 4. A fresh dial takes the new snapshot; the old socket keeps its
    // binding, pinned by readback: sending on it now would have no
    // route, which is the honest outcome of a stale snapshot.
    let fresh = UdpSocket::bind("0.0.0.0:0").expect("fresh socket");
    let rebound = protect(&OutboundFdHook::BindDefaultIface, fresh.as_raw_fd())
        .expect("protect the fresh socket");
    assert_eq!(
        rebound.as_deref(),
        Some("v1a"),
        "new dials bind the new default"
    );
    assert_eq!(
        bound_device(guarded.as_raw_fd()),
        "v0a",
        "old binding persists"
    );
    let flipped_target = format!("10.201.0.2:{LISTEN_PORT}");
    for _ in 0..3 {
        fresh
            .send_to(b"flipped", &flipped_target)
            .expect("send escapes via v1a");
        std::thread::sleep(Duration::from_millis(100));
    }

    // The plain send from step 1 is waiting in the TUN queue: the
    // datagram the rule captured back, read off the device itself.
    // Scan rather than assume the first packet is the one.
    let mut looped = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline {
        if let Some(candidate) = read_packet(&tun, 200)
            && candidate[0] >> 4 == 4
            && candidate[9] == 17
            && candidate[16..20] == [203, 0, 113, 10]
        {
            looped = Some(candidate);
            break;
        }
    }
    assert!(looped.is_some(), "the plain datagram never reached the TUN");
}

fn bound_device(fd: std::os::fd::RawFd) -> String {
    let mut name = [0u8; 16];
    let mut len = name.len() as u32;
    // Safety: a fixed-size buffer with its length passed alongside.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_mut_ptr().cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0);
    let n = name.iter().position(|&b| b == 0).unwrap_or(len as usize);
    String::from_utf8_lossy(&name[..n]).into_owned()
}

/// Attach to an existing TUN device and return the fd holding it open.
fn attach_tun(name: &str) -> std::fs::File {
    let tun = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .expect("open /dev/net/tun");
    #[repr(C)]
    struct Ifreq {
        name: [u8; 16],
        flags: std::os::raw::c_short,
    }
    let mut request = Ifreq {
        name: [0; 16],
        // IFF_TUN | IFF_NO_PI: raw IP at offset zero, no info header.
        flags: 0x1001,
    };
    request.name[..name.len()].copy_from_slice(name.as_bytes());
    // Safety: a fixed-layout struct passed to one ioctl by pointer.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::ioctl(tun.as_raw_fd(), 0x400454ca, &mut request) };
    assert_eq!(rc, 0, "TUNSETIFF on {name}");
    tun
}

/// Read one packet off a TUN fd, waiting up to `timeout_ms`.
fn read_packet(tun: &std::fs::File, timeout_ms: i32) -> Option<Vec<u8>> {
    let mut poller = libc::pollfd {
        fd: tun.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // Safety: a fixed-layout struct passed to poll by pointer.
    #[allow(unsafe_code)]
    let ready = unsafe { libc::poll(&mut poller, 1, timeout_ms) };
    if ready != 1 {
        return None;
    }
    let mut packet = [0u8; 2048];
    // Safety: a fixed-size buffer with its length passed alongside.
    #[allow(unsafe_code)]
    let n = unsafe { libc::read(tun.as_raw_fd(), packet.as_mut_ptr().cast(), packet.len()) };
    if n <= 0 {
        return None;
    }
    Some(packet[..n as usize].to_vec())
}
