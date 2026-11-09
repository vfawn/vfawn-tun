// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Per-flow kernel bypass (056 P1/P2) against a real kernel.
//!
//! The parent owns the "internet": real TCP and UDP servers on
//! 10.201.0.2 and a ping target on 10.201.0.3, in the root namespace.
//! The body runs inside a fresh namespace whose only uplink is a veth
//! to that network, with a full [`Instance`] (`auto_route` plus
//! `auto_redirect`) and a handler that judges by destination port, for
//! TCP and UDP alike:
//!
//! * 8080 Bypass — reaches the real server, never touches the device,
//!   arrives from the uplink's address (masquerade), every packet of
//!   it (not just the first);
//! * 8081 Bypass after a 1.5 s judgement — every datagram sent while
//!   the judgement runs gets the verdict, and other flows are judged
//!   meanwhile (sing-tun's non-blocking judging);
//! * 9090 Accept — captured, echoed by the handler, the server never
//!   sees it;
//! * 7070 Reject — refused (a kernel reset for TCP);
//! * 6060 Drop — nothing comes back.
//!
//! ICMP echo to 10.201.0.3 is bypassed, to 10.201.0.2 captured (and
//! dropped by the handler).
//!
//! Then: strict reverse-path filtering with `src_valid_mark`; the
//! fallback when the queue is taken or `nft` is missing (the instance
//! runs on the plain capture); a LAN client forwarded through the
//! instance, with and without the LAN excluded; orderly shutdown
//! leaves no table, `kill -9` leaves one the sweep removes.
//!
//! A second test measures throughput with iperf3: direct, direct with
//! conntrack running, and bypassed.
//!
//! ```sh
//! sudo -E cargo test -p vfawn --release --test auto_redirect_linux -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(target_os = "linux")]

use ipnet::IpNet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vfawn::Instance;
use vfawn_core::{
    Action, DnsMode, FlowInfo, IcmpPacket, SessionHandler, TcpSession, UdpSession, Verdict,
    VfawnConfig,
};

const NS: &str = "vfawn056";
const LAN_NS: &str = "vfawn056c";
const LAN: &str = "10.202.0.0/24";
const LAN_CLIENT: &str = "10.202.0.2";
const IP: &str = "/usr/sbin/ip";
const NFT: &str = "/usr/sbin/nft";
const TUN: &str = "vfawn56";
const SERVER: &str = "10.201.0.2";
const UPLINK: &str = "10.201.0.1";
const PING_BYPASS: &str = "10.201.0.3";
const BULK: usize = 32 << 20;

fn run(mut cmd: Command) -> String {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "command failed: {cmd:?}\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn sh(line: &str) -> Command {
    let mut c = Command::new("sh");
    c.args(["-c", line]);
    c
}

fn in_ns(line: &str) -> Command {
    sh(&format!("ip netns exec {NS} {line}"))
}

fn env_is(key: &str, value: &str) -> bool {
    std::env::var(key).as_deref() == Ok(value)
}

/// The body's namespace with one uplink to the root namespace.
fn topology() {
    let _ = sh(&format!(
        "ip netns del {NS}; ip netns del {LAN_NS}; ip link del v56b"
    ))
    .output();
    run(sh(&format!("ip netns add {NS}")));
    // No IPv6 chatter on the device: the bypass proof counts its packets.
    run(in_ns("sysctl -q -w net.ipv6.conf.default.disable_ipv6=1"));
    run(sh(&format!(
        "ip link add v56a type veth peer name v56b && ip link set v56a netns {NS} && \
         ip addr add {SERVER}/24 dev v56b && ip addr add {PING_BYPASS}/24 dev v56b && \
         ip link set v56b up"
    )));
    run(in_ns(&format!(
        "sh -c 'ip link set lo up && ip addr add {UPLINK}/24 dev v56a && \
         ip link set v56a up && ip route add default via {SERVER}'"
    )));
    run(in_ns("sysctl -q -w net.ipv4.conf.all.rp_filter=0"));
    run(in_ns("sysctl -q -w net.ipv4.conf.default.rp_filter=0"));
}

/// A LAN behind the body's namespace: a client namespace routed
/// through it, and the root namespace routing replies back.
fn lan_topology() {
    run(sh(&format!("ip netns add {LAN_NS}")));
    run(sh(&format!(
        "ip link add v56c type veth peer name v56d && \
         ip link set v56c netns {LAN_NS} && ip link set v56d netns {NS}"
    )));
    run(sh(&format!(
        "ip netns exec {LAN_NS} sh -c 'ip link set lo up && \
         ip addr add {LAN_CLIENT}/24 dev v56c && ip link set v56c up && \
         ip route add default via 10.202.0.1'"
    )));
    run(in_ns(
        "sh -c 'ip addr add 10.202.0.1/24 dev v56d && ip link set v56d up && \
         sysctl -q -w net.ipv4.ip_forward=1 && sysctl -q -w net.ipv4.conf.v56d.rp_filter=0'",
    ));
    run(sh(&format!("ip route replace {LAN} via {UPLINK}")));
}

#[test]
#[ignore]
fn auto_redirect_end_to_end() {
    match std::env::var("VFAWN_056_BODY").as_deref() {
        Ok("probe") => return body_probe(),
        Ok("hold") => return body_hold(),
        Ok("sweep") => return body_sweep(),
        Ok("nomark") => return body_nomark(),
        Ok("fallback") => return body_fallback(),
        Ok("forward") => return body_forward(),
        Ok("lan") => return body_lan(),
        Ok("dns") => return body_dns(),
        Ok("openwrt") => return body_openwrt(),
        _ => {}
    }

    topology();
    for port in [8080, 9090, 7070, 6060] {
        serve(port);
    }
    for port in [8080, 8081, 9090, 7070, 6060, 53] {
        serve_udp(port);
    }

    // Loose reverse-path filtering first, then strict with the mark
    // honored: the reply direction carries the restored bypass mark.
    body("probe", &[]);
    body("dns", &[]);
    run(in_ns(
        "sh -c 'sysctl -q -w net.ipv4.conf.all.rp_filter=1 && \
         sysctl -q -w net.ipv4.conf.v56a.rp_filter=1 && \
         sysctl -q -w net.ipv4.conf.v56a.src_valid_mark=1'",
    ));
    body("probe", &[("VFAWN_056_QUICK", "1")]);
    // The risk the rp_filter warning names: strict filtering without
    // src_valid_mark. Reported, not asserted — it is the host's call.
    run(in_ns("sysctl -q -w net.ipv4.conf.v56a.src_valid_mark=0"));
    body("nomark", &[]);
    run(in_ns("sysctl -q -w net.ipv4.conf.all.rp_filter=0"));
    run(in_ns("sysctl -q -w net.ipv4.conf.v56a.rp_filter=0"));

    // No bypass support: the queue already taken, or no nft binary.
    // The instance starts anyway and every flow takes the device.
    body("fallback", &[("VFAWN_056_FALLBACK", "queue")]);
    body(
        "fallback",
        &[
            ("VFAWN_056_FALLBACK", "nft"),
            ("PATH", "/usr/local/cargo/bin:/usr/bin:/bin"),
        ],
    );

    // A LAN routed through the instance.
    lan_topology();
    body("forward", &[]);
    // OpenWrt's firewall4, played by a stand-in on the body's PATH.
    std::fs::create_dir_all(FW4_DIR).unwrap();
    std::fs::write(format!("{FW4_DIR}/fw4"), FW4_STAND_IN).unwrap();
    run(sh(&format!(
        "chmod +x {FW4_DIR}/fw4 && mkdir -p /etc/nftables.d"
    )));
    let path = format!("{FW4_DIR}:{}", std::env::var("PATH").unwrap_or_default());
    body("openwrt", &[("PATH", &path)]);
    let _ = std::fs::remove_dir_all(FW4_DIR);

    // kill -9: the table outlives the process; the sweep removes it.
    let mut held = spawn_body("hold", &[]);
    // The harness prints its own header lines ahead of the body's.
    let ready = BufReader::new(held.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
        .any(|line| line.trim() == "ready");
    assert!(ready, "the held body came up");
    run(sh(&format!("kill -9 {}", held.id())));
    let _ = held.wait();
    let tables = run(in_ns("nft list tables"));
    assert!(
        tables.contains("vfawn_redirect_"),
        "a crash leaves the table behind for the sweep: {tables}"
    );
    body("sweep", &[]);
    let tables = run(in_ns("nft list tables"));
    assert!(!tables.contains("vfawn_"), "swept clean: {tables}");

    run(sh(&format!(
        "ip netns del {NS}; ip netns del {LAN_NS}; ip route del {LAN}"
    )));
    println!("056 P1 e2e passed");
}

/// A real server in the root namespace: banner with the peer address,
/// then echo.
fn serve(port: u16) {
    let listener = TcpListener::bind((SERVER, port)).expect("bind server");
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let peer = stream.peer_addr().unwrap().ip();
                let _ = writeln!(stream, "server {peer}");
                let mut buf = vec![0u8; 1 << 16];
                while let Ok(n) = stream.read(&mut buf)
                    && n > 0
                {
                    if stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
}

/// Re-run this test binary as a body inside `ns`. The `ip` binary is
/// named by path: a body may run with a `PATH` that hides `nft`, and
/// both live in the same directory.
const FW4_DIR: &str = "/tmp/vfawn056-fw4";

/// firewall4's reload, as far as these rules are concerned: rebuild
/// `inet fw4`, every /etc/nftables.d include first, then its own input
/// and forward chains, dropping by policy behind their established
/// flows. (Real fw4 accepts sing-tun's include the same way: checked by
/// hand on the openwrt-24.10 rootfs, our rules landing at the head of
/// both chains, the policy staying drop.)
const FW4_STAND_IN: &str = r#"#!/bin/sh
[ "$1" = reload ] || exit 1
nft -f - <<EOF
table inet fw4
delete table inet fw4
table inet fw4 {
	include "/etc/nftables.d/*.nft"
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		ct state established,related accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
	}
}
EOF
"#;

/// A real UDP server: every datagram answered with the peer address.
fn serve_udp(port: u16) {
    let socket = UdpSocket::bind((SERVER, port)).expect("bind udp server");
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((_, peer)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(format!("server {}", peer.ip()).as_bytes(), peer);
        }
    });
}

fn spawn_in(ns: &str, test: &str, mode: &str, env: &[(&str, &str)]) -> Child {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = Command::new(IP);
    cmd.args(["netns", "exec", ns])
        .arg(exe)
        .args(["--exact", test, "--ignored", "--nocapture"])
        .env("VFAWN_056_BODY", mode)
        .stdout(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.spawn().expect("spawn body")
}

fn spawn_body(mode: &str, env: &[(&str, &str)]) -> Child {
    spawn_in(NS, "auto_redirect_end_to_end", mode, env)
}

fn finish(child: Child, mode: &str) {
    let out = child.wait_with_output().unwrap();
    print!("{}", String::from_utf8_lossy(&out.stdout));
    assert!(out.status.success(), "body {mode} failed");
}

fn body(mode: &str, env: &[(&str, &str)]) {
    finish(spawn_body(mode, env), mode);
}

// --- Body side -----------------------------------------------------------

struct ByPort;

#[async_trait::async_trait]
impl SessionHandler for ByPort {
    fn judge_flow(&self, flow: &FlowInfo, _first: &[u8]) -> Verdict {
        if flow.network == vfawn_core::Network::Icmp {
            return if flow.destination.ip().to_string() == PING_BYPASS {
                Verdict::Bypass
            } else {
                Verdict::Accept
            };
        }
        match flow.destination.port() {
            8080 | 53 => Verdict::Bypass,
            8081 => {
                std::thread::sleep(Duration::from_millis(1500));
                Verdict::Bypass
            }
            7070 => Verdict::Reject,
            6060 => Verdict::Drop,
            _ => Verdict::Accept,
        }
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        let mut buf = [0u8; 16384];
        while let Ok(n) = session.read(&mut buf).await
            && n > 0
        {
            let _ = session.write(&buf[..n]).await;
        }
        let _ = session.shutdown_write().await;
    }

    async fn on_udp(&self, mut session: UdpSession) {
        let mut buf = [0u8; 2048];
        while let Ok((n, remote)) = session.recv(&mut buf).await {
            let _ = session.send(&buf[..n], &remote).await;
        }
    }

    async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
        Action::Drop
    }
}

fn start_instance() -> Instance {
    start_with(Arc::new(ByPort), &[])
}

fn start_with(handler: Arc<dyn SessionHandler>, excluded: &[IpNet]) -> Instance {
    start_dns(handler, excluded, DnsMode::Disabled)
}

fn start_dns(handler: Arc<dyn SessionHandler>, excluded: &[IpNet], dns: DnsMode) -> Instance {
    start_config(handler, excluded, &[], dns)
}

fn start_config(
    handler: Arc<dyn SessionHandler>,
    excluded: &[IpNet],
    captured: &[IpNet],
    dns: DnsMode,
) -> Instance {
    start_custom(handler, |config| {
        config.route.route_exclude_address = excluded.to_vec();
        config.route.route_address = captured.to_vec();
        config.dns.mode = dns;
    })
}

fn start_custom(
    handler: Arc<dyn SessionHandler>,
    tweak: impl FnOnce(&mut VfawnConfig),
) -> Instance {
    let mut config = VfawnConfig::default();
    config.device.name = Some(TUN.into());
    config.device.inet4_address = vec!["198.18.0.1/15".parse().unwrap()];
    config.route.auto_route = true;
    config.route.auto_redirect.enabled = true;
    tweak(&mut config);
    let mut instance = Instance::new(config, Arc::clone(&handler)).expect("instance");
    instance.start(handler).expect("start");
    std::thread::sleep(Duration::from_millis(300));
    instance
}

/// Wait until nothing is crossing the device: connections a previous
/// scenario accepted may still be closing through it, and their last
/// packets must not be counted against the next.
fn settle() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last = tun_tx();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(300));
        let now = tun_tx();
        if now == last {
            return;
        }
        last = now;
    }
}

fn tun_tx() -> u64 {
    std::fs::read_to_string(format!("/sys/class/net/{TUN}/statistics/tx_packets"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn connect(port: u16, timeout: Duration) -> std::io::Result<TcpStream> {
    let addr: SocketAddr = format!("{SERVER}:{port}").parse().unwrap();
    TcpStream::connect_timeout(&addr, timeout)
}

fn banner(stream: &TcpStream) -> String {
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    line.trim().to_string()
}

/// Push `BULK` bytes through the server's echo; the throughput in MB/s.
fn bulk(stream: TcpStream) -> f64 {
    let mut reader = stream.try_clone().unwrap();
    let start = Instant::now();
    let writer = std::thread::spawn(move || {
        let mut stream = stream;
        let chunk = vec![0x5au8; 1 << 16];
        for _ in 0..BULK / chunk.len() {
            stream.write_all(&chunk).unwrap();
        }
        stream
    });
    let mut buf = vec![0u8; 1 << 16];
    let mut got = 0;
    while got < BULK {
        let n = reader.read(&mut buf).unwrap();
        assert!(n > 0, "echo ended early at {got}");
        got += n;
    }
    drop(writer.join().unwrap());
    BULK as f64 / start.elapsed().as_secs_f64() / 1e6
}

fn body_probe() {
    let quick = std::env::var("VFAWN_056_QUICK").is_ok();
    let direct = (!quick).then(|| {
        let stream = connect(8080, Duration::from_secs(3)).expect("direct connect");
        assert_eq!(banner(&stream), format!("server {UPLINK}"));
        bulk(stream)
    });

    let mut instance = start_instance();
    let rules = run(sh("ip rule"));
    assert!(rules.contains("fwmark 0x2024 lookup main"), "{rules}");
    let table = run(sh(&format!("nft list table inet vfawn_redirect_{TUN}")));
    assert!(table.contains("queue"), "{table}");

    // Bypass: the real server answers, from the uplink's address, and
    // not one packet of the connection crosses the device.
    let before = tun_tx();
    let stream = connect(8080, Duration::from_secs(3)).expect("bypass connect");
    assert_eq!(
        banner(&stream),
        format!("server {UPLINK}"),
        "bypassed flow reaches the server masqueraded"
    );
    let bypassed = bulk(stream);
    let crossed = tun_tx() - before;
    assert_eq!(crossed, 0, "bypassed packets crossed the device");
    match direct {
        Some(direct) => println!(
            "bypass {bypassed:.0} MB/s vs direct {direct:.0} MB/s ({:.0}%)",
            bypassed / direct * 100.0
        ),
        None => println!("bypass under strict rp_filter: {bypassed:.0} MB/s"),
    }

    if !quick {
        // Accept: captured and echoed by the handler; the server's
        // banner would arrive first if the flow had escaped.
        let before = tun_tx();
        let mut stream = connect(9090, Duration::from_secs(3)).expect("accept connect");
        stream.write_all(b"ping").unwrap();
        let mut echo = [0u8; 4];
        stream.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping", "the handler, not the server, answered");
        assert!(tun_tx() > before, "accepted flow crossed the device");

        // Reject: a kernel reset, fast.
        let start = Instant::now();
        let refused = connect(7070, Duration::from_secs(3)).expect_err("reject");
        assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
        assert!(start.elapsed() < Duration::from_secs(1));

        // Drop: nothing comes back.
        let dropped = connect(6060, Duration::from_secs(1)).expect_err("drop");
        assert_eq!(dropped.kind(), std::io::ErrorKind::TimedOut);

        storm();
        udp_and_icmp();
        judging_never_blocks();
    }

    // Orderly shutdown: the table and the bypass rule are gone.
    instance.shutdown().unwrap();
    let tables = run(sh("nft list tables"));
    assert!(!tables.contains("vfawn_redirect_"), "{tables}");
    let rules = run(sh("ip rule"));
    assert!(!rules.contains("0x2024"), "{rules}");
    println!("probe ok");
}

/// A verdict storm: three verdicts interleaved at well over a thousand
/// new connections a second, each with its own outcome checked, and
/// the queue reporting no drop. A SYN the queue had failed open on
/// would land on the captured path and answer with the echo instead
/// of the server's banner.
fn storm() {
    const THREADS: usize = 20;
    const EACH: usize = 60;
    let start = Instant::now();
    let workers: Vec<_> = (0..THREADS)
        .map(|t| {
            std::thread::spawn(move || {
                for i in 0..EACH {
                    match (t + i) % 3 {
                        0 => {
                            let stream = connect(8080, Duration::from_secs(3)).expect("bypass");
                            assert_eq!(banner(&stream), format!("server {UPLINK}"));
                        }
                        1 => {
                            let mut stream = connect(9090, Duration::from_secs(3)).expect("accept");
                            stream.write_all(b"pong").unwrap();
                            let mut echo = [0u8; 4];
                            stream.read_exact(&mut echo).unwrap();
                            assert_eq!(&echo, b"pong");
                        }
                        _ => {
                            let refused = connect(7070, Duration::from_secs(3)).expect_err("rst");
                            assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
                        }
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("storm worker");
    }
    let rate = (THREADS * EACH) as f64 / start.elapsed().as_secs_f64();
    let ours = queue_stats(100).expect("queue 100 bound");
    println!(
        "storm {} flows at {rate:.0}/s, queue stats {ours:?}",
        THREADS * EACH
    );
    assert_eq!((ours[5], ours[6]), (0, 0), "the queue dropped nothing");
}

/// One datagram to the server's `port`, the first answer (if any).
fn udp_exchange(socket: &UdpSocket, port: u16, payload: &[u8]) -> std::io::Result<String> {
    udp_exchange_with(socket, SERVER, port, payload)
}

fn udp_exchange_with(
    socket: &UdpSocket,
    host: &str,
    port: u16,
    payload: &[u8],
) -> std::io::Result<String> {
    socket.send_to(payload, (host, port))?;
    let mut buf = [0u8; 2048];
    let (n, _) = socket.recv_from(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

fn udp_socket(timeout: Duration) -> UdpSocket {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.set_read_timeout(Some(timeout)).unwrap();
    socket
}

fn ping(target: &str) -> bool {
    Command::new("ping")
        .args(["-c", "3", "-i", "0.2", "-W", "1", target])
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// The datagram verdicts (056 P2). A bypassed UDP flow reaches the
/// real server masqueraded, every datagram of it outside the device;
/// an accepted one is the handler's (captured, its later datagrams
/// riding the capture mark rather than the queue); drop and reject
/// never reach the server. ICMP echo: bypassed to one host, captured
/// (and dropped by the handler) toward the other.
fn udp_and_icmp() {
    settle();
    let socket = udp_socket(Duration::from_secs(2));
    let before = tun_tx();
    for _ in 0..20 {
        assert_eq!(
            udp_exchange(&socket, 8080, b"hello").expect("udp bypass"),
            format!("server {UPLINK}")
        );
    }
    assert_eq!(
        tun_tx() - before,
        0,
        "bypassed datagrams crossed the device"
    );

    let socket = udp_socket(Duration::from_secs(2));
    let before_queue = queue_stats(100).expect("queue bound")[7];
    for _ in 0..20 {
        assert_eq!(
            udp_exchange(&socket, 9090, b"ping").expect("udp accept"),
            "ping"
        );
    }
    // One judgement for the flow: the capture mark keeps the rest out
    // of the queue.
    let judged = queue_stats(100).unwrap()[7] - before_queue;
    assert_eq!(
        judged, 1,
        "datagrams of one accepted flow queued {judged} times"
    );

    let socket = udp_socket(Duration::from_secs(1));
    assert!(
        udp_exchange(&socket, 6060, b"x").is_err(),
        "udp drop answered"
    );
    let socket = udp_socket(Duration::from_secs(1));
    // Refused in the stack: either no answer or an ICMP error, never
    // the server's.
    if let Ok(answer) = udp_exchange(&socket, 7070, b"x") {
        assert!(
            !answer.starts_with("server"),
            "udp reject reached the server"
        );
    }

    let before = tun_tx();
    assert!(ping(PING_BYPASS), "bypassed ping");
    assert_eq!(tun_tx() - before, 0, "bypassed echo crossed the device");
    assert!(!ping(SERVER), "captured ping is the handler's to drop");
    println!("udp and icmp ok");
}

/// DNS against the pre-match, by mode (sing-tun's exclude rules): with
/// DNS hijacked, a local query never reaches the queue, so even a host
/// that would bypass port 53 cannot carry it past the hijack — the
/// stack takes it, and the handler (an echo) answers. Without the
/// hijack, the same verdict sends it to the real server.
fn body_dns() {
    let mut instance = start_dns(Arc::new(ByPort), &[], DnsMode::Hijack);
    let judged = queue_stats(100).expect("queue bound")[7];
    let before = tun_tx();
    let socket = udp_socket(Duration::from_secs(2));
    assert_eq!(
        udp_exchange(&socket, 53, b"query").expect("hijacked answer"),
        "query",
        "the hijack, not the server, answered"
    );
    assert_eq!(
        queue_stats(100).unwrap()[7],
        judged,
        "a hijacked query was queued"
    );
    assert!(tun_tx() > before, "the hijacked query crossed the device");
    instance.shutdown().unwrap();

    let mut instance = start_dns(Arc::new(ByPort), &[], DnsMode::Disabled);
    let socket = udp_socket(Duration::from_secs(2));
    assert_eq!(
        udp_exchange(&socket, 53, b"query").expect("bypassed dns"),
        format!("server {UPLINK}")
    );
    instance.shutdown().unwrap();
    println!("dns ok");
}

/// sing-tun judges without blocking packet processing: a 1.5 s
/// judgement holds only its own flow — every datagram sent meanwhile
/// waits for, and gets, that verdict — while another flow is judged
/// and connected in the meantime.
fn judging_never_blocks() {
    settle();
    let before = tun_tx();
    let slow = std::thread::spawn(|| {
        let socket = udp_socket(Duration::from_secs(4));
        let start = Instant::now();
        for _ in 0..5 {
            socket.send_to(b"slow", (SERVER, 8081)).unwrap();
        }
        let mut answers = 0;
        let mut buf = [0u8; 64];
        while answers < 5 && socket.recv_from(&mut buf).is_ok() {
            answers += 1;
        }
        (answers, start.elapsed())
    });
    std::thread::sleep(Duration::from_millis(200));
    let start = Instant::now();
    let stream = connect(8080, Duration::from_secs(3)).expect("connect during a slow judgement");
    assert_eq!(banner(&stream), format!("server {UPLINK}"));
    let fast = start.elapsed();
    let (answers, slow_elapsed) = slow.join().unwrap();
    println!(
        "slow flow: {answers}/5 datagrams answered after {slow_elapsed:?}; \
         another flow connected in {fast:?} meanwhile"
    );
    assert_eq!(
        answers, 5,
        "every datagram of the judged flow got its verdict"
    );
    assert!(slow_elapsed >= Duration::from_millis(1400));
    assert!(
        fast < Duration::from_millis(700),
        "a slow judgement blocked the queue"
    );
    assert_eq!(tun_tx() - before, 0);
}

/// This namespace's line for queue `num` in
/// /proc/net/netfilter/nfnetlink_queue: queue, portid, waiting, copy
/// mode, copy range, queue_dropped, user_dropped, sequence, 1.
fn queue_stats(num: u64) -> Option<Vec<u64>> {
    std::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue")
        .unwrap_or_default()
        .lines()
        .map(|l| {
            l.split_whitespace()
                .map(|f| f.parse().unwrap_or(0))
                .collect::<Vec<_>>()
        })
        .find(|f| f.first() == Some(&num))
}

/// Echo through the handler: what a flow on the captured path gets.
/// A flow that reached the real server would read its banner instead.
fn assert_echoed(port: u16) {
    let mut stream = connect(port, Duration::from_secs(3)).expect("captured connect");
    stream.write_all(b"ping").unwrap();
    let mut echo = [0u8; 4];
    stream.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"ping", "port {port}: the handler answered");
}

/// The bypass cannot install; the instance must still start, leave no
/// table and no bound queue of its own, and carry every flow — the one
/// judged Bypass included — over the device.
fn body_fallback() {
    let nft_missing = env_is("VFAWN_056_FALLBACK", "nft");
    // Someone else's reader on our queue number.
    let _taken = (!nft_missing).then(|| {
        let mut queue = nfq::Queue::open().unwrap();
        queue.bind(100).unwrap();
        queue
    });
    let held_by_other = queue_stats(100).map(|f| f[1]);

    let mut instance = start_instance();
    let tables = run(sh(&format!("{NFT} list tables")));
    assert!(!tables.contains("vfawn_redirect_"), "{tables}");
    // A failed install releases what it bound; a taken queue stays the
    // other reader's.
    assert_eq!(queue_stats(100).map(|f| f[1]), held_by_other);

    let before = tun_tx();
    assert_echoed(8080);
    assert_echoed(9090);
    assert!(tun_tx() > before, "every flow crossed the device");
    instance.shutdown().unwrap();
    println!(
        "fallback ({}) ok",
        if nft_missing {
            "nft missing"
        } else {
            "queue taken"
        }
    );
}

/// The instance as a LAN gateway. Without the LAN excluded, a bypassed
/// connection's replies (addressed to the LAN client) would be
/// captured like any other packet; only the mark restored on the reply
/// direction sends them out the LAN port. With it excluded — the
/// configuration a gateway needs for its captured flows anyway — every
/// verdict works for the LAN client.
fn body_forward() {
    let lan = |mode: &str| {
        let child = spawn_in(
            LAN_NS,
            "auto_redirect_end_to_end",
            "lan",
            &[("VFAWN_056_LAN", mode)],
        );
        finish(child, mode);
    };

    let mut instance = start_instance();
    let before = tun_tx();
    // Twice: the first transfer over a fresh LAN pays its warm-up.
    lan("bypass");
    lan("bypass");
    assert_eq!(tun_tx() - before, 0, "forwarded bypass crossed the device");
    instance.shutdown().unwrap();

    let mut instance = start_with(Arc::new(ByPort), &[LAN.parse().unwrap()]);
    let before = tun_tx();
    lan("bypass");
    assert_eq!(tun_tx() - before, 0, "forwarded bypass crossed the device");
    lan("rest");
    assert!(tun_tx() > before, "forwarded accept crossed the device");

    // Docker comes up after us: its forward path drops by policy, and
    // the monitor puts our two exceptions at the head of DOCKER-USER.
    docker_up();
    wait_for_docker_rules(2);
    lan("rest");
    // Both directions went through our exceptions, not around them:
    // DOCKER-USER's own rule returns into a dropping policy.
    let chain = run(sh(&format!("{NFT} list chain ip filter DOCKER-USER")));
    let counted = chain
        .lines()
        .filter(|l| l.contains("Docker compatibility") && !l.contains("packets 0 "))
        .count();
    assert_eq!(counted, 2, "both exceptions carried the flow: {chain}");
    // Docker restarts and rebuilds its tables.
    run(sh(&format!("{NFT} delete table ip filter")));
    docker_up();
    wait_for_docker_rules(2);
    lan("rest");
    // One of ours deleted from outside comes back; a stray copy goes.
    let handle = docker_rule_handles()[0];
    run(sh(&format!(
        "{NFT} delete rule ip filter DOCKER-USER handle {handle}"
    )));
    wait_for_docker_rules(2);
    nft_f(&format!(
        "insert rule ip filter DOCKER-USER oifname \"{TUN}\" counter accept \
         comment \"!vfawn_redirect_{TUN}: Docker compatibility output to tun\"\n"
    ));
    wait_for_docker_rules(2);
    // Shutdown takes ours and leaves Docker's.
    instance.shutdown().unwrap();
    assert_eq!(
        docker_rule_handles().len(),
        0,
        "our docker rules outlived us"
    );
    let chain = run(sh(&format!("{NFT} list chain ip filter DOCKER-USER")));
    assert!(
        chain.contains("return"),
        "docker's own rule survived: {chain}"
    );

    // Docker already there when we start: the rules go in with us.
    let mut instance = start_with(Arc::new(ByPort), &[LAN.parse().unwrap()]);
    assert_eq!(docker_rule_handles().len(), 2, "rules installed at start");
    lan("rest");
    instance.shutdown().unwrap();
    assert_eq!(docker_rule_handles().len(), 0);
    run(sh(&format!("{NFT} delete table ip filter")));

    // A bounded capture (route_address): the server's address is
    // outside it, the ping target's inside. Outside, nothing is judged
    // and nothing enters the device — local or forwarded alike.
    let captured: IpNet = format!("{PING_BYPASS}/32").parse().unwrap();
    let mut instance = start_config(Arc::new(ByPort), &[], &[captured], DnsMode::Disabled);
    let judged = queue_stats(100).expect("queue bound")[7];
    let before = tun_tx();
    let socket = udp_socket(Duration::from_secs(2));
    assert_eq!(
        udp_exchange(&socket, 9090, b"ping").expect("uncaptured udp"),
        format!("server {UPLINK}"),
        "outside the range the real server answers"
    );
    lan("outside");
    assert_eq!(tun_tx() - before, 0, "uncaptured flows crossed the device");
    assert_eq!(
        queue_stats(100).unwrap()[7],
        judged,
        "uncaptured flows were judged"
    );
    // Inside the range: judged (accepted) and answered by the handler.
    let socket = udp_socket(Duration::from_secs(2));
    assert_eq!(
        udp_exchange_with(&socket, PING_BYPASS, 9090, b"ping").expect("captured udp"),
        "ping"
    );
    assert!(tun_tx() > before, "the captured flow crossed the device");
    assert!(
        queue_stats(100).unwrap()[7] > judged,
        "the captured flow was judged"
    );
    instance.shutdown().unwrap();

    // Interface filters (sing-tun's Include/ExcludeInterface). "lo" is
    // this host's own traffic, v56d the LAN.
    let lan_net: IpNet = LAN.parse().unwrap();
    let local_echoed = || {
        let socket = udp_socket(Duration::from_secs(2));
        assert_eq!(
            udp_exchange(&socket, 9090, b"ping").expect("local udp"),
            "ping"
        );
    };
    let local_direct = || {
        let socket = udp_socket(Duration::from_secs(2));
        assert_eq!(
            udp_exchange(&socket, 9090, b"ping").expect("local udp"),
            format!("server {UPLINK}")
        );
    };
    for (include, exclude) in [(vec!["lo"], vec![]), (vec![], vec!["v56d"])] {
        // The LAN excluded as a gateway excludes it: replies from the
        // uplink to a LAN client arrive on another interface, and only
        // the destination keeps them out of the capture (sing-tun's
        // rules capture them the same way).
        let mut instance = start_custom(Arc::new(ByPort), |c| {
            c.route.include_interface = include.iter().map(|s| s.to_string()).collect();
            c.route.exclude_interface = exclude.iter().map(|s| s.to_string()).collect();
            c.route.route_exclude_address = vec![lan_net];
        });
        let rules = run(sh("ip rule"));
        let judged = queue_stats(100).unwrap()[7];
        lan("outside");
        assert_eq!(
            queue_stats(100).unwrap()[7],
            judged,
            "the spared LAN was judged"
        );
        local_echoed();
        instance.shutdown().unwrap();
        println!("include {include:?} exclude {exclude:?}: LAN spared, local captured\n{rules}");
    }
    let mut instance = start_custom(Arc::new(ByPort), |c| {
        c.route.include_interface = vec!["v56d".into()];
        c.route.route_exclude_address = vec![lan_net];
    });
    let table = run(sh(&format!("{NFT} list table inet vfawn_redirect_{TUN}")));
    assert!(
        !table.contains("output_prematch"),
        "no output chain: {table}"
    );
    local_direct();
    lan("captured-udp");
    instance.shutdown().unwrap();
    println!("include [v56d]: local spared, LAN captured");
    println!("forward ok (docker, capture range and interface filters included)");
}

/// Docker's iptables-nft shape, as far as forwarding is concerned: a
/// forward chain dropping by policy after jumping to DOCKER-USER, whose
/// own rule returns.
fn docker_up() {
    let script = "table ip filter {\n\
         \tchain DOCKER-USER {\n\t\tcounter return\n\t}\n\
         \tchain FORWARD {\n\t\ttype filter hook forward priority 0; policy drop;\n\
         \t\tjump DOCKER-USER\n\t}\n}\n";
    nft_f(script);
}

fn nft_f(script: &str) {
    let mut child = Command::new(NFT)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "nft -f: {script}");
}

/// Handles of our compatibility rules in DOCKER-USER.
fn docker_rule_handles() -> Vec<u32> {
    let out = Command::new(NFT)
        .args(["-a", "list", "chain", "ip", "filter", "DOCKER-USER"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("Docker compatibility"))
        .filter_map(|l| l.rsplit("handle ").next()?.trim().parse().ok())
        .collect()
}

fn wait_for_docker_rules(count: usize) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while docker_rule_handles().len() != count {
        assert!(
            Instant::now() < deadline,
            "docker rules: {:?}, wanted {count}",
            docker_rule_handles()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// OpenWrt (sing-tun's configureOpenWRTFirewall4): with fw4 running,
/// the capture's include goes in at start — fw4's forward path, which
/// drops by policy, then carries LAN flows into the device through our
/// rules — and comes out at shutdown.
fn body_openwrt() {
    let include = format!("/etc/nftables.d/0-vfawn_redirect_{TUN}-auto-redirect.nft");
    run(sh("fw4 reload"));
    assert!(!run(sh(&format!("{NFT} list table inet fw4"))).contains("Accept traffic from tun"));

    let mut instance = start_custom(Arc::new(ByPort), |c| {
        c.route.route_exclude_address = vec![LAN.parse().unwrap()];
    });
    assert!(std::path::Path::new(&include).exists(), "the include is in");
    let child = spawn_in(
        LAN_NS,
        "auto_redirect_end_to_end",
        "lan",
        &[("VFAWN_056_LAN", "rest")],
    );
    finish(child, "rest");
    let forward = run(sh(&format!("{NFT} list chain inet fw4 forward")));
    let counted = forward
        .lines()
        .filter(|l| l.contains("Accept traffic from tun") && !l.contains("packets 0 "))
        .count();
    assert_eq!(counted, 2, "both forward rules carried the flow: {forward}");
    assert!(
        forward.contains("policy drop"),
        "fw4's policy kept: {forward}"
    );

    instance.shutdown().unwrap();
    assert!(
        !std::path::Path::new(&include).exists(),
        "the include is out"
    );
    assert!(
        !run(sh(&format!("{NFT} list table inet fw4"))).contains("Accept traffic from tun"),
        "fw4 reloaded without our rules"
    );
    run(sh(&format!("{NFT} delete table inet fw4")));
    println!("openwrt ok");
}

/// The LAN client's side of [`body_forward`].
fn body_lan() {
    if env_is("VFAWN_056_LAN", "captured-udp") {
        let socket = udp_socket(Duration::from_secs(2));
        assert_eq!(
            udp_exchange(&socket, 9090, b"ping").expect("lan captured udp"),
            "ping"
        );
        println!("lan captured ok");
    } else if env_is("VFAWN_056_LAN", "outside") {
        // Forwarded, untouched: the server sees the LAN client itself.
        let socket = udp_socket(Duration::from_secs(2));
        assert_eq!(
            udp_exchange(&socket, 9090, b"ping").expect("lan uncaptured udp"),
            format!("server {LAN_CLIENT}")
        );
        println!("lan outside the capture ok");
    } else if env_is("VFAWN_056_LAN", "bypass") {
        let stream = connect(8080, Duration::from_secs(3)).expect("lan bypass connect");
        // Forwarded, not masqueraded: the server sees the LAN client.
        assert_eq!(banner(&stream), format!("server {LAN_CLIENT}"));
        let rate = bulk(stream);
        println!("lan bypass {rate:.0} MB/s");
    } else {
        assert_echoed(9090);
        let refused = connect(7070, Duration::from_secs(3)).expect_err("lan reject");
        assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
        println!("lan accept and reject ok");
    }
}

fn body_nomark() {
    let mut instance = start_instance();
    match connect(8080, Duration::from_secs(2)) {
        Ok(stream) => println!(
            "strict rp_filter without src_valid_mark: bypass connected ({})",
            banner(&stream)
        ),
        Err(e) => println!("strict rp_filter without src_valid_mark: bypass failed ({e})"),
    }
    instance.shutdown().unwrap();
}

fn body_hold() {
    let _instance = start_instance();
    println!("ready");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn body_sweep() {
    let report = vfawn_platform::linux::cleanup_nftables(None).unwrap();
    println!("swept {:?}", report.nftables_tables);
}

// --- Throughput ----------------------------------------------------------

const ROUNDS: usize = 5;
const SECONDS: &str = "3";
const PROBE_TABLE: &str = "vfawn056probe";

/// iperf3 servers that die with the test, panicking or not: a leaked
/// server holds the harness's output pipe open forever.
struct Servers(Vec<Child>);

impl Drop for Servers {
    fn drop(&mut self) {
        for server in &mut self.0 {
            let _ = server.kill();
            let _ = server.wait();
        }
    }
}

/// Throughput on a three-step ladder, each step measured every round:
///
/// 1. direct — the namespace has no netfilter rule, so conntrack is
///    not even running;
/// 2. direct with conntrack — what any netfilter-based bypass pays
///    before its own rules (sing-tun's included);
/// 3. bypassed — conntrack plus this feature's rules: the per-packet
///    mark restore and re-route, and the masquerade.
///
/// The device path the bypass replaces is not re-measured here; this
/// bed's figures for it are on record (034 baseline, 046 dispatch).
#[test]
#[ignore]
fn auto_redirect_throughput() {
    if env_is("VFAWN_056_BODY", "bench") {
        return body_bench();
    }
    topology();
    let _servers = Servers(vec![
        Command::new("iperf3")
            .args(["-s", "-B", SERVER, "-p", "5201"])
            .stdout(Stdio::null())
            .spawn()
            .expect("iperf3 server"),
    ]);
    std::thread::sleep(Duration::from_millis(300));
    finish(
        spawn_in(NS, "auto_redirect_throughput", "bench", &[]),
        "bench",
    );
    run(sh(&format!("ip netns del {NS}")));
}

struct BypassAll;

#[async_trait::async_trait]
impl SessionHandler for BypassAll {
    fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
        Verdict::Bypass
    }
    async fn on_tcp(&self, _session: TcpSession) {}
    async fn on_udp(&self, _session: UdpSession) {}
    async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
        Action::Drop
    }
}

/// One iperf3 run from this namespace: receiver-side Gbit/s.
fn iperf() -> f64 {
    let out = Command::new("iperf3")
        .args(["-c", SERVER, "-p", "5201", "-t", SECONDS, "-J"])
        .output()
        .expect("iperf3 client");
    let json = String::from_utf8_lossy(&out.stdout);
    let tail = &json[json.find("\"sum_received\"").expect("iperf3 summary")..];
    let field = &tail[tail.find("\"bits_per_second\":").unwrap() + 18..];
    let value: f64 = field
        .trim_start()
        .split([',', '\n', '}'])
        .next()
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    value / 1e9
}

/// This process's CPU time so far, in clock ticks (utime + stime).
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<&str> = stat[stat.rfind(')').unwrap() + 2..]
        .split_whitespace()
        .collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn body_bench() {
    let (mut direct, mut tracked, mut bypass, mut cpu) = (vec![], vec![], vec![], vec![]);
    for round in 0..ROUNDS {
        direct.push(iperf());

        run(sh(&format!(
            "{NFT} 'add table inet {PROBE_TABLE}; \
             add chain inet {PROBE_TABLE} out {{ type filter hook output priority 0; }}; \
             add rule inet {PROBE_TABLE} out ct state new counter'"
        )));
        tracked.push(iperf());
        run(sh(&format!("{NFT} delete table inet {PROBE_TABLE}")));

        let mut instance = start_with(Arc::new(BypassAll), &[]);
        let before = (tun_tx(), cpu_ticks());
        bypass.push(iperf());
        let after = (tun_tx(), cpu_ticks());
        instance.shutdown().unwrap();
        assert_eq!(after.0 - before.0, 0, "bypassed packets crossed the device");
        cpu.push((after.1 - before.1) as f64);

        println!(
            "round {round}: direct {:.1}, direct+conntrack {:.1}, bypass {:.1} Gbit/s",
            direct[round], tracked[round], bypass[round]
        );
    }
    let (d, t, b) = (median(direct), median(tracked), median(bypass));
    println!(
        "median of {ROUNDS} x {SECONDS}s: direct {d:.1}, direct+conntrack {t:.1} ({:.0}%), \
         bypass {b:.1} Gbit/s ({:.0}% of direct, {:.0}% of direct+conntrack); \
         instance CPU during a bypass run: {:.0} ticks",
        t / d * 100.0,
        b / d * 100.0,
        b / t * 100.0,
        median(cpu),
    );
    // The 056 acceptance line (revised 2026-11-10 from 90%): the
    // per-packet re-route and the source rewrite a default-into-the-
    // device capture forces cost about 12% at these memory-speed
    // rates; see 056 §九.
    assert!(b >= 0.8 * d, "bypass {b:.1} below 80% of direct {d:.1}");
}
