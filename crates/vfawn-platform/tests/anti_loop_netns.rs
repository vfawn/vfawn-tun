// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The anti-loop demo, asserted with packets rather than eyes.
//!
//! One namespace, two veth pairs, one TUN. A policy rule captures every
//! destination into the TUN the way a real capture setup does. Then:
//!
//! * an ordinary socket's datagram lands on the TUN (the loop, pinned
//!   as the control group);
//! * a socket the hook bound to the first veth escapes through it;
//! * after the default route moves to the second veth, a freshly
//!   protected socket escapes through the new one, while the old
//!   socket keeps its old binding (snapshots do not migrate).
//!
//! The test re-executes itself inside the namespace, so the body runs
//! our real `protect` chain against the namespace's routing table.
//!
//! ```sh
//! sudo -E cargo test -p vfawn-platform --test anti_loop_netns -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use vfawn_core::OutboundFdHook;
use vfawn_platform::linux::protect;

const NS: &str = "vfawn023";
const DST: &str = "203.0.113.10:9";
const MARKER: &str = "203.0.113.10";

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

/// Set the marker this test uses to decide whether it is the body.
fn in_body() -> bool {
    std::env::var("VFAWN_ANTILOOP_BODY").is_ok()
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

    // Control: with no binding, the destination routes into the TUN.
    let control = in_ns(&["ip", "route", "get", MARKER])
        .output()
        .expect("route get");
    let text = String::from_utf8_lossy(&control.stdout).to_string();
    assert!(
        text.contains("dev tun0"),
        "control must route into the TUN, got: {text}"
    );

    // Both veth peers get a capture outside the namespace; the TUN side
    // needs none, the body reads the loop straight off the device fd.
    let v0_capture = spawn_capture("v0b");
    let v1_capture = spawn_capture("v1b");
    std::thread::sleep(std::time::Duration::from_secs(1));

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

    stop_capture(v0_capture);
    stop_capture(v1_capture);

    let on_v0 = captured_packets("/tmp/vfawn023-v0.pcap");
    let on_v1 = captured_packets("/tmp/vfawn023-v1.pcap");

    run(ip(&["netns", "del", NS]));
    let _ = std::fs::remove_file("/tmp/vfawn023-v0.pcap");
    let _ = std::fs::remove_file("/tmp/vfawn023-v1.pcap");

    assert!(
        on_v0 >= 1,
        "the protected socket escaped through v0 (tcpdump said: {})",
        capture_stderr("v0b")
    );
    assert!(
        on_v1 >= 1,
        "after the flip, a fresh socket escaped through v1 (tcpdump said: {})",
        capture_stderr("v1b")
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
        .send_to(b"loop", DST)
        .expect("send is accepted into the TUN");

    // 2. The escape: protect resolves the default interface (v0a here)
    // and binds the socket to it.
    let guarded = UdpSocket::bind("0.0.0.0:0").expect("guarded socket");
    let bound = protect(&OutboundFdHook::BindDefaultIface, guarded.as_raw_fd())
        .expect("protect the socket");
    assert_eq!(bound.as_deref(), Some("v0a"));
    guarded
        .send_to(b"escape", DST)
        .expect("send escapes via v0a");

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
    // binding (pinned by readback, not by sending: after the flip the
    // old interface no longer carries a route to the destination, and
    // an unsendable socket is the honest outcome of a stale snapshot).
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
    fresh
        .send_to(b"flipped", DST)
        .expect("send escapes via v1a");

    // The plain send from step 1 is waiting in the TUN queue: the
    // datagram the rule captured back, read off the device itself.
    let looped = read_packet(&tun, 3000).expect("a packet queued on the TUN");
    assert_eq!(looped[0] >> 4, 4, "IPv4");
    assert_eq!(looped[9], 17, "UDP");
    assert_eq!(&looped[12..16], &[203, 0, 113, 10], "captured destination");
}

/// Attach to an existing TUN device and return the fd holding it open.
fn attach_tun(name: &str) -> std::fs::File {
    use std::os::fd::AsRawFd;
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
    use std::os::fd::AsRawFd;
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

fn spawn_capture(device: &str) -> Child {
    let file = format!("/tmp/vfawn023-{device}.pcap");
    let err = format!("/tmp/vfawn023-{device}.err");
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(&err);
    // Packet-buffered writes so a hard stop still leaves the capture
    // readable; stderr lands in a file for failure diagnostics.
    let mut cmd = Command::new("tcpdump");
    cmd.args(["-i", device, "-nn", "-U", "-w", &file, "-c", "8", "udp"]);
    cmd.stdout(Stdio::null())
        .stderr(std::fs::File::create(&err).expect("stderr sink"));
    cmd.spawn().expect("spawn tcpdump")
}

fn capture_stderr(device: &str) -> String {
    std::fs::read_to_string(format!("/tmp/vfawn023-{device}.err"))
        .unwrap_or_else(|_| "(no diagnostics)".into())
}

fn stop_capture(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn captured_packets(file: &str) -> usize {
    let output = Command::new("tcpdump")
        .args(["-nn", "-r", file])
        .stderr(Stdio::null())
        .output()
        .expect("read capture back");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(MARKER))
        .count()
}
