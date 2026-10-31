// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Phase-one end-to-end acceptance: the whole product inside one
//! namespace, asserted by what the kernel and the wire actually do.
//!
//! One body process runs a real [`Instance`] with `auto_route` on, a
//! rules-plus-echo handler, and DNS hijack; the parent sets up the
//! namespace and asserts from outside through `ip`, `dig`, and probe
//! sockets. Six scenarios:
//!
//! 1. one-flag takeover: capture rules in place, the physical subnet
//!    still direct, captured traffic echoed back through the TUN;
//! 2. self-heal: a network flap re-triggers reconciliation and the
//!    capture keeps working;
//! 3. `kill -9` plus the cleanup command leaves zero residue, and an
//!    orderly shutdown removes its own rules;
//! 4. hot update: a wider exclusion takes effect while running;
//! 5. mixed verdicts over real sockets: accept echoes, reject refuses
//!    fast, drop goes silent, ICMP drops without killing the instance;
//! 6. DNS hijack answers a real `dig` at a far resolver address, and
//!    disabled mode leaves the query uncaptured at the handler;
//! 7. an IPv6 session echoes end to end.
//!
//! ```sh
//! sudo -E cargo test -p vfawn --test e2e_linux -- --ignored --test-threads=1 --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
use vfawn::Instance;
use vfawn_core::{
    Action, FlowInfo, IcmpPacket, SessionHandler, TcpSession, UdpSession, Verdict, VfawnConfig,
};

const NS: &str = "vfawn026";
const TUN: &str = "vfawn0";
const RUN: &str = "/tmp/vfawn026";
const PHYS: &str = "10.200.0.0/24";
const FAR: &str = "203.0.113.10";
const VIRTUAL_DNS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

fn run(mut cmd: Command) {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "command failed: {:?}\n{}{}",
        cmd,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn out(cmd: &mut Command) -> String {
    let out = cmd.output().expect("spawn");
    String::from_utf8_lossy(&out.stdout).into_owned()
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

/// The scenario the re-executed body should run.
fn scenario() -> String {
    std::env::var("VFAWN_E2E_SCENARIO").unwrap_or_default()
}

fn in_body() -> bool {
    std::env::var("VFAWN_E2E_BODY").is_ok()
}

#[test]
#[ignore]
fn phase_one_end_to_end() {
    if in_body() {
        body();
        return;
    }

    let start = Instant::now();
    let _ = std::fs::remove_dir_all(RUN);
    std::fs::create_dir_all(RUN).unwrap();
    let _ = ip(&["netns", "del", NS]).output();
    let _ = ip(&["link", "del", "v0b"]).output();

    run(ip(&["netns", "add", NS]));
    run(in_ns(&[
        "sysctl",
        "-q",
        "-w",
        "net.ipv6.conf.default.disable_ipv6=1",
    ]));
    run(ip(&[
        "link", "add", "v0a", "type", "veth", "peer", "name", "v0b",
    ]));
    run(ip(&["link", "set", "v0a", "netns", NS]));
    run(ip(&["addr", "add", "10.200.0.2/24", "dev", "v0b"]));
    run(ip(&["link", "set", "v0b", "up"]));
    run(in_ns(&["ip", "link", "set", "lo", "up"]));
    run(in_ns(&["ip", "addr", "add", "10.200.0.1/24", "dev", "v0a"]));
    run(in_ns(&["ip", "link", "set", "v0a", "up"]));
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

    // A listener on the physical peer proves exclusion: datagrams the
    // capture must NOT take arrive here.
    let physical_hits = listener_hits("physical", "10.200.0.2");

    // The body, one scenario at a time, driven by phases the parent
    // requests through files.
    let exe = std::env::current_exe()
        .expect("test binary")
        .to_string_lossy()
        .into_owned();

    for phase in ["hijack", "flap-heal", "hot-update", "verdicts", "v6"] {
        spawn_body(&exe, phase);
        match phase {
            "hijack" => assert_hijack(),
            "flap-heal" => assert_flap_heal(),
            "hot-update" => assert_hot_update(&physical_hits),
            "verdicts" => assert_verdicts(),
            "v6" => assert_v6(),
            _ => unreachable!(),
        }
        stop_body();
    }

    // The kill -9 and residue scenario runs last, on the same namespace.
    spawn_body(&exe, "kill9");
    assert_kill9_residue_free();

    run(ip(&["netns", "del", NS]));
    let _ = std::fs::remove_dir_all(RUN);
    println!("phase-one e2e passed in {:?}", start.elapsed());
}

// --- Parent-side assertions ----------------------------------------------

/// Hijack mode: a real dig at a far resolver gets our answer, and the
/// handler saw the query against the virtual address.
fn assert_hijack() {
    wait_file("ready");
    let dig = out(&mut in_ns(&[
        "dig",
        "+time=2",
        "+tries=1",
        "@8.8.8.8",
        "example.com",
    ]));
    assert!(
        dig.contains("status: REFUSED"),
        "dig saw our responder: {dig}"
    );
    assert!(
        dig.contains("server 8.8.8.8"),
        "the answer came back from the address asked: {dig}"
    );
    let queries = std::fs::read_to_string(format!("{RUN}/dns-queries.log")).unwrap();
    assert!(
        queries.contains(&format!("{VIRTUAL_DNS}:53")),
        "the handler faced the virtual resolver: {queries}"
    );

    // Disabled mode: same dig, the query never reaches a handler.
    write_file("mode", "disabled");
    wait_file("mode-set");
    let dig = out(&mut in_ns(&[
        "dig",
        "+time=1",
        "+tries=1",
        "@8.8.8.8",
        "example.com",
    ]));
    assert!(
        !dig.contains("status: REFUSED"),
        "no responder in disabled mode: {dig}"
    );
    let count = std::fs::read_to_string(format!("{RUN}/dns-queries.log"))
        .unwrap()
        .lines()
        .count();
    assert_eq!(count, 1, "the disabled-mode query was not delivered");
}

/// A link flap re-triggers reconciliation; the capture survives.
fn assert_flap_heal() {
    wait_file("ready");
    assert_capture_rules_present();

    // Down goes the physical link; the monitor must notice, and the
    // auto-reconciler must put the capture back over the healed link.
    run(in_ns(&["ip", "link", "set", "v0a", "down"]));
    std::thread::sleep(Duration::from_millis(700));
    run(in_ns(&["ip", "link", "set", "v0a", "up"]));
    run(in_ns(&["ip", "addr", "add", "10.200.0.1/24", "dev", "v0a"]));
    run(in_ns(&[
        "ip",
        "route",
        "replace",
        "default",
        "via",
        "10.200.0.2",
        "dev",
        "v0a",
    ]));

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if capture_rules_present() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_capture_rules_present();

    // And the capture still carries traffic.
    assert_udp_echo("203.0.113.10", 5001, b"after-flap");
}

/// Widening the exclusion mid-flight moves traffic off the TUN.
fn assert_hot_update(physical_hits: &Arc<AtomicU64>) {
    wait_file("ready");
    assert_udp_echo(FAR, 5001, b"captured");

    let before = physical_hits.load(Ordering::SeqCst);
    write_file("phase", "exclude-far");
    wait_file("phase-set");

    let deadline = Instant::now() + Duration::from_secs(3);
    while physical_hits.load(Ordering::SeqCst) == before && Instant::now() < deadline {
        let _ = probe_udp(FAR, 5001, b"excluded");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        physical_hits.load(Ordering::SeqCst) > before,
        "the far address now egresses the physical link"
    );
}

/// Port-based verdicts through real sockets, plus an ICMP drop that
/// must not take the instance down with it.
fn assert_verdicts() {
    wait_file("ready");

    // Accepted TCP echoes.
    let echoed = probe_tcp("203.0.113.10", 5001, b"tcp-echo");
    assert_eq!(echoed, Some("tcp-echo".to_string()));

    // Rejected TCP refuses fast: an RST, not a timeout.
    let refused = probe_tcp_refused("203.0.113.10", 5002);
    assert!(refused, "port 5002 refuses instead of hanging");

    // Dropped TCP stays silent.
    let silent = probe_tcp("203.0.113.10", 5003, b"nobody home");
    assert_eq!(silent, None);

    // Accepted UDP echoes.
    assert_udp_echo("203.0.113.10", 5001, b"udp-echo");

    // ICMP is dropped, and the instance survives it.
    let _ = in_ns(&["ping", "-c", "1", "-W", "1", FAR]).output();
    let echoed = probe_tcp("203.0.113.10", 5001, b"still-alive");
    assert_eq!(echoed, Some("still-alive".to_string()));
}

/// A v6 session echoes end to end through the same device.
fn assert_v6() {
    wait_file("ready");
    let script = "import socket;s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b'v6-echo',('fd00::2',5001));print(s.recvfrom(64)[0].decode())";
    let result = out(&mut in_ns(&["python3", "-c", script]));
    assert_eq!(result.trim(), "v6-echo");
}

/// kill -9 leaves rules by design; the cleanup command removes them all.
fn assert_kill9_residue_free() {
    wait_file("ready");
    assert_capture_rules_present();

    // Hard kill: no orderly shutdown ran.
    let pid = std::fs::read_to_string(format!("{RUN}/body.pid")).unwrap();
    let mut kill = Command::new("kill");
    kill.args(["-9", pid.trim()]);
    run(kill);
    std::thread::sleep(Duration::from_millis(300));

    let cleanup = format!(
        "{}/../../vfawn-bin",
        std::env::current_exe().unwrap().parent().unwrap().display()
    );
    run(in_ns(&[&cleanup]));
    assert!(
        !capture_rules_present(),
        "cleanup removed every tagged rule"
    );
    let table = out(&mut in_ns(&["ip", "route", "show", "table", "2022"]));
    assert_eq!(table.trim(), "", "the dedicated table is empty");
}

fn assert_capture_rules_present() {
    assert!(capture_rules_present(), "capture rules are installed");
}

fn capture_rules_present() -> bool {
    let rules = out(&mut in_ns(&["ip", "rule", "show"]));
    let table = out(&mut in_ns(&["ip", "route", "show", "table", "2022"]));
    rules.contains("lookup 2022") && table.contains(TUN)
}

// --- Parent-side helpers -------------------------------------------------

/// A UDP listener in the root namespace, counting what escapes.
fn listener_hits(name: &str, bind: &str) -> Arc<AtomicU64> {
    let hits = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&hits);
    let barrier = Arc::new(Barrier::new(2));
    let gate = Arc::clone(&barrier);
    let bind = bind.to_string();
    let name = name.to_string();
    std::thread::Builder::new()
        .name(name)
        .spawn(move || {
            let socket = std::net::UdpSocket::bind(format!("{bind}:5201")).expect("bind");
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            gate.wait();
            loop {
                let mut buf = [0u8; 64];
                if socket.recv_from(&mut buf).is_ok() {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .expect("spawn listener");
    barrier.wait();
    hits
}

fn spawn_body(exe: &str, scenario_name: &str) {
    let _ = std::fs::remove_file(format!("{RUN}/ready"));
    let _ = std::fs::remove_file(format!("{RUN}/phase-set"));
    let _ = std::fs::remove_file(format!("{RUN}/mode-set"));
    let child = in_ns(&[exe])
        .arg("phase_one_end_to_end")
        .arg("--ignored")
        .arg("--exact")
        .arg("--test-threads=1")
        .env("VFAWN_E2E_BODY", "1")
        .env("VFAWN_E2E_SCENARIO", scenario_name)
        .stdout(std::fs::File::create(format!("{RUN}/body.out")).unwrap())
        .stderr(std::fs::File::create(format!("{RUN}/body.err")).unwrap())
        .spawn()
        .expect("spawn body");
    // The body writes its own pid once running; keeping the spawn handle
    // leaks nothing because the parent outlives every scenario.
    std::mem::forget(child);
}

fn stop_body() {
    // Removing the pid file is the stop request; the body answers with
    // `stopped` after an orderly shutdown, which is itself under test:
    // its rules must be gone by then.
    let _ = std::fs::remove_file(format!("{RUN}/body.pid"));
    wait_file("stopped");
    let _ = std::fs::remove_file(format!("{RUN}/stopped"));
    assert!(
        !capture_rules_present(),
        "an orderly shutdown removed its own rules"
    );
}

fn wait_file(name: &str) {
    let path = format!("{RUN}/{name}");
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if std::path::Path::new(&path).exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "timed out waiting for {name}; body stderr: {}",
        std::fs::read_to_string(format!("{RUN}/body.err")).unwrap_or_default()
    );
}

fn write_file(name: &str, content: &str) {
    std::fs::write(format!("{RUN}/{name}"), content).unwrap();
}

/// One UDP exchange through whatever route the namespace has.
fn assert_udp_echo(dst: &str, port: u16, payload: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(reply) = probe_udp(dst, port, payload) {
            assert_eq!(reply, payload);
            return;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    panic!("no UDP echo from {dst}:{port}");
}

fn probe_udp(dst: &str, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let script = format!(
        "import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1);s.sendto(sys.stdin.buffer.read(),({dst:?},{port}));sys.stdout.buffer.write(s.recv(2048))"
    );
    let out = Command::new("ip")
        .args(["netns", "exec", NS, "python3", "-c", &script])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload)
                .expect("write probe");
            child.wait_with_output()
        })
        .expect("probe");
    if out.status.success() && !out.stdout.is_empty() {
        Some(out.stdout)
    } else {
        None
    }
}

fn probe_tcp(dst: &str, port: u16, payload: &[u8]) -> Option<String> {
    let script = format!(
        "import socket,sys;s=socket.create_connection(({dst:?},{port}),2);s.sendall(sys.stdin.buffer.read());s.settimeout(2);d=s.recv(4096);sys.stdout.write(d.decode())"
    );
    let out = Command::new("ip")
        .args(["netns", "exec", NS, "python3", "-c", &script])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload)
                .expect("write probe");
            child.wait_with_output()
        })
        .expect("probe");
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

fn probe_tcp_refused(dst: &str, port: u16) -> bool {
    let script = format!(
        "import socket,sys\ntry:\n socket.create_connection(({dst:?},{port}),1)\n sys.exit(1)\nexcept ConnectionRefusedError:\n sys.exit(0)\nexcept Exception:\n sys.exit(2)"
    );
    let out = Command::new("ip")
        .args(["netns", "exec", NS, "python3", "-c", &script])
        .output()
        .expect("probe");
    out.status.success()
}

// --- The body: a real Instance under each scenario -----------------------

struct E2eHandler {
    udp_echoes: AtomicU64,
}

#[async_trait::async_trait]
impl SessionHandler for E2eHandler {
    fn judge_flow(&self, flow: &FlowInfo, _first: &[u8]) -> Verdict {
        match flow.destination.port() {
            5001 => Verdict::Accept,
            5002 => Verdict::Reject,
            5003 => Verdict::Drop,
            _ => Verdict::Accept,
        }
    }

    async fn on_tcp(&self, mut session: TcpSession) {
        let mut buf = [0u8; 4096];
        while let Ok(n) = session.read(&mut buf).await {
            if n == 0 || session.write(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = session.shutdown_write().await;
    }

    async fn on_udp(&self, mut session: UdpSession) {
        // DNS questions get a well-formed refusal so `dig` can parse
        // the answer; everything else echoes.
        let mut buf = [0u8; 1500];
        if let Ok((n, peer)) = session.recv(&mut buf).await {
            if session.flow().destination.port() == 53 {
                let mut log = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(format!("{RUN}/dns-queries.log"))
                    .unwrap();
                use std::io::Write;
                let _ = writeln!(log, "{}", session.flow().destination);
                let _ = session.send(&refused(&buf[..n]), &peer).await;
                return;
            }
            self.udp_echoes.fetch_add(1, Ordering::SeqCst);
            let _ = session.send(&buf[..n], &peer).await;
        }
    }

    async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
        Action::Drop
    }
}

/// The smallest DNS answer a resolver client accepts: same id, response
/// bit set, question echoed, zero answers, rcode REFUSED.
fn refused(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    if answer.len() < 12 {
        return answer;
    }
    answer[2] = 0x81; // response, recursion desired
    answer[3] = 0x05; // recursion available, rcode REFUSED
    answer[7] = 0; // answer count
    answer[9] = 0; // authority
    answer[11] = 0; // additional
    answer
}

fn body() {
    std::fs::write(format!("{RUN}/body.pid"), std::process::id().to_string()).unwrap();

    let mode = scenario();
    let mut config = base_config();
    match mode.as_str() {
        "v6" => {
            config.device.inet6_address = vec!["fd00::1/64".parse().unwrap()];
            // The v6 session rides the on-link route; no capture needed.
            config.route.auto_route = false;
        }
        "kill9" | "flap-heal" | "verdicts" => {}
        "hot-update" => {
            // Starts captured; the parent requests a wider exclusion.
        }
        _ => {}
    }

    let handler = Arc::new(E2eHandler {
        udp_echoes: AtomicU64::new(0),
    });
    let mut instance = Instance::new(config.clone(), handler.clone()).expect("instance");
    instance.start(handler.clone()).expect("start");
    write_file("ready", "1");

    // Follow-up phases the parent requests through files.
    loop {
        match mode.as_str() {
            "hot-update" => {
                if let Ok(phase) = std::fs::read_to_string(format!("{RUN}/phase"))
                    && phase.trim() == "exclude-far"
                {
                    let mut updated = base_config();
                    updated.route.auto_route = true;
                    updated
                        .route
                        .route_exclude_address
                        .push(format!("{FAR}/32").parse().unwrap());
                    instance.apply_config(&updated).expect("hot update");
                    write_file("phase-set", "1");
                    let _ = std::fs::remove_file(format!("{RUN}/phase"));
                }
            }
            "hijack" => {
                if let Ok(requested) = std::fs::read_to_string(format!("{RUN}/mode"))
                    && requested.trim() == "disabled"
                {
                    // Disabled mode never intercepts: restart the
                    // instance with interception off.
                    instance.shutdown().expect("shutdown");
                    let mut disabled = base_config();
                    disabled.dns.mode = vfawn_core::DnsMode::Disabled;
                    let mut fresh = Instance::new(disabled, handler.clone()).expect("instance");
                    fresh.start(handler.clone()).expect("start");
                    instance = fresh;
                    write_file("mode-set", "1");
                    let _ = std::fs::remove_file(format!("{RUN}/mode"));
                }
            }
            _ => {}
        }
        if !std::path::Path::new(&format!("{RUN}/body.pid")).exists() {
            instance.shutdown().expect("shutdown");
            write_file("stopped", "1");
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn base_config() -> VfawnConfig {
    let mut config = VfawnConfig::default();
    config.device.name = Some(TUN.to_string());
    config.device.mtu = 1500;
    config.device.inet4_address = vec!["198.18.0.1/15".parse().unwrap()];
    config.route.auto_route = true;
    config
        .route
        .route_exclude_address
        .push(PHYS.parse().unwrap());
    config
}
