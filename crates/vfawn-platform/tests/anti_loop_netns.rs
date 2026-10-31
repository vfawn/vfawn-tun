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

    // Three captures: the TUN inside the namespace, both veth peers
    // outside it. Counts are read from the pcaps at the end.
    let tun0_capture = spawn_capture(Some(NS), "tun0");
    let v0_capture = spawn_capture(None, "v0b");
    let v1_capture = spawn_capture(None, "v1b");
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

    stop_capture(tun0_capture);
    stop_capture(v0_capture);
    stop_capture(v1_capture);

    let on_tun = captured_packets("/tmp/vfawn023-tun0.pcap");
    let on_v0 = captured_packets("/tmp/vfawn023-v0.pcap");
    let on_v1 = captured_packets("/tmp/vfawn023-v1.pcap");

    run(ip(&["netns", "del", NS]));
    let _ = std::fs::remove_file("/tmp/vfawn023-tun0.pcap");
    let _ = std::fs::remove_file("/tmp/vfawn023-v0.pcap");
    let _ = std::fs::remove_file("/tmp/vfawn023-v1.pcap");

    assert!(
        on_tun >= 1,
        "the unbound socket's datagram looped into the TUN"
    );
    assert!(on_v0 >= 1, "the protected socket escaped through v0");
    assert!(
        on_v1 >= 1,
        "after the flip, a fresh socket escaped through v1"
    );
}

/// What runs inside the namespace: real sockets, real `protect` calls.
fn body() {
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

fn spawn_capture(namespace: Option<&str>, device: &str) -> Child {
    let file = format!("/tmp/vfawn023-{device}.pcap");
    let _ = std::fs::remove_file(&file);
    let mut cmd = if namespace.is_some() {
        in_ns(&[
            "tcpdump", "-i", device, "-nn", "-w", &file, "-c", "8", "udp",
        ])
    } else {
        let mut c = Command::new("tcpdump");
        c.args(["-i", device, "-nn", "-w", &file, "-c", "8", "udp"]);
        c
    };
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    cmd.spawn().expect("spawn tcpdump")
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
