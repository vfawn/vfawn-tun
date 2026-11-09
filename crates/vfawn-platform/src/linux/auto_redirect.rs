// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Per-flow kernel bypass, after sing-tun's auto-redirect pre-match
//! (`nfqueue_linux.go`, `redirect_nftables.go`): judge a flow on its
//! first packet, before the packet reaches the device.
//!
//! Netfilter queues each new flow's first packet — a TCP connection's
//! pure SYN, a UDP flow's first datagram, an ICMP echo request — to this
//! process; `judge_flow` answers, and the answer becomes the flow's fate
//! (sing-tun's `applyVerdict`, nftables path):
//!
//! * `Bypass` — the packet re-enters its chain carrying the bypass mark,
//!   the mark is mirrored into conntrack, and every later packet of the
//!   flow picks it back up. A policy rule (planned by the route engine)
//!   sends marked traffic to the main table, so the flow never touches
//!   the device or the stack.
//! * `Reject` — a TCP SYN re-enters carrying the reset mark, which a rule
//!   turns into a TCP reset; any other flow re-enters with the capture
//!   mark and the stack refuses it.
//! * `Drop` — discarded.
//! * anything else — a TCP SYN is accepted unmarked and the capture
//!   routes it into the device; any other flow re-enters with the capture
//!   mark, so its later packets are not queued again. Either way the
//!   stack judges it again.
//!
//! Judging never blocks the queue (sing-tun's "judge flows without
//! blocking packet processing"): the reader groups packets by flow, a
//! worker judges each flow once, and every packet of the flow that
//! arrived meanwhile gets the same verdict.
//!
//! Two consequences of a capture that routes into the device by default
//! (sing-tun's mark mode routes to the main table by default and marks
//! its way in) shape the rules beyond sing-tun's:
//!
//! * A local socket picks its source address from the route it saw when
//!   it first sent — the device's. Re-routing to the main table does not
//!   rewrite it, so bypassed local flows are masqueraded.
//! * Replies of a bypassed forwarded flow would be captured too, so the
//!   bypass mark is restored in both directions, first thing.
//!
//! The rules live in a table of their own (`vfawn_redirect_<if>`),
//! installed and removed in one `nft -f` transaction. The `vfawn_`
//! prefix puts it in the crash-safety scanner's sweep.

use ipnet::IpNet;
use std::collections::HashMap;
use std::io::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;
use vfawn_core::{FlowInfo, Network, SessionHandler, Verdict};
use vfawn_wire::{IpProtocol, Ipv4Header, Ipv6Header, TcpFlags, TcpHeader, UdpHeader, V6Payload};

/// How long the queue reader blocks before it rechecks the stop flag.
const RECV_TIMEOUT: Duration = Duration::from_millis(200);
/// sing-tun's queue configuration: `MaxPacketLen: 0xFFFF`,
/// `MaxQueueLen: 4096`, GSO packets accepted.
const COPY_RANGE: u16 = 0xFFFF;
const QUEUE_MAX_LEN: u32 = 4096;

/// Everything the rules and the reader need.
#[derive(Debug, Clone)]
pub struct RedirectParams<'a> {
    /// The capture device.
    pub interface: &'a str,
    /// The device's own addresses: the source a bypassed local flow
    /// carries until masquerade rewrites it.
    pub tun_addresses: &'a [IpNet],
    /// The capture range (`route_address`); empty means everything. A
    /// destination outside it is never queued.
    pub captured: &'a [IpNet],
    /// Destinations the capture already spares; never queued.
    pub excluded: &'a [IpNet],
    /// Incoming interfaces the capture takes ("lo" for this host's own
    /// traffic); empty means every one.
    pub include_interface: &'a [String],
    /// Incoming interfaces the capture spares; ignored with an include
    /// list, as sing-tun ignores it.
    pub exclude_interface: &'a [String],
    /// This process's own socket mark; zero when unused.
    pub escape_mark: u32,
    /// DNS is hijacked in the stack: local port-53 flows are never
    /// judged, so no verdict can carry one past the hijack.
    pub dns_hijack: bool,
    pub input_mark: u32,
    pub output_mark: u32,
    pub reset_mark: u32,
    pub queue: u16,
}

/// The marks a verdict writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marks {
    pub input: u32,
    pub output: u32,
    pub reset: u32,
}

/// What the reader tells the kernel about one queued packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueDecision {
    /// Continue unmarked.
    Accept,
    /// Discard.
    Drop,
    /// Re-enter the chain carrying this mark.
    Repeat(u32),
}

/// A flow's identity while it is being judged: sing-tun's `flowKey`.
/// ICMP echo carries its identifier where the ports would be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: IpProtocol,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// A queued packet read as sing-tun's `parsePreMatchPacket` reads it.
#[derive(Debug)]
pub struct PreMatch<'a> {
    pub key: FlowKey,
    /// The flow as `judge_flow` sees it, the same shape the stack hands
    /// over for the same flow (ICMP without ports).
    pub flow: FlowInfo,
    /// The UDP payload; empty for TCP and ICMP.
    pub first_packet: &'a [u8],
}

/// Parse a queued packet. `None` for anything that is not the first
/// packet of a flow sing-tun judges: a pure TCP SYN, a UDP datagram, an
/// ICMP or ICMPv6 echo request; later fragments never qualify.
pub fn parse_prematch(packet: &[u8]) -> Option<PreMatch<'_>> {
    let (source, destination, protocol, transport) = match packet.first()? >> 4 {
        4 => {
            let (ip, payload) = Ipv4Header::parse(packet).ok()?;
            if ip.fragment_offset != 0 {
                return None;
            }
            (IpAddr::V4(ip.src), IpAddr::V4(ip.dst), ip.protocol, payload)
        }
        6 => {
            let (ip, rest) = Ipv6Header::parse(packet).ok()?;
            let payload = V6Payload::walk(ip.next_header, rest).ok()?;
            if payload.fragment.is_some_and(|f| f.offset != 0) {
                return None;
            }
            (
                IpAddr::V6(ip.src),
                IpAddr::V6(ip.dst),
                payload.protocol,
                payload.bytes,
            )
        }
        _ => return None,
    };
    let (network, ports, first_packet) = match protocol {
        IpProtocol::Tcp => {
            let (tcp, _) = TcpHeader::parse(transport).ok()?;
            if !tcp.flags.contains(TcpFlags::SYN) || tcp.flags.contains(TcpFlags::ACK) {
                return None;
            }
            (Network::Tcp, (tcp.src_port, tcp.dst_port), &[][..])
        }
        IpProtocol::Udp => {
            let (udp, payload) = UdpHeader::parse(transport).ok()?;
            (Network::Udp, (udp.src_port, udp.dst_port), payload)
        }
        IpProtocol::Icmp | IpProtocol::Icmpv6 => {
            let echo_request = match protocol {
                IpProtocol::Icmp if source.is_ipv4() => 8,
                IpProtocol::Icmpv6 if source.is_ipv6() => 128,
                _ => return None,
            };
            if transport.len() < 8 || transport[0] != echo_request || transport[1] != 0 {
                return None;
            }
            let identifier = u16::from_be_bytes([transport[4], transport[5]]);
            (Network::Icmp, (identifier, identifier), &[][..])
        }
        _ => return None,
    };
    let key = FlowKey {
        protocol,
        source: SocketAddr::new(source, ports.0),
        destination: SocketAddr::new(destination, ports.1),
    };
    let flow_ports = if network == Network::Icmp {
        (0, 0)
    } else {
        ports
    };
    Some(PreMatch {
        key,
        flow: FlowInfo {
            network,
            source: SocketAddr::new(source, flow_ports.0),
            destination: SocketAddr::new(destination, flow_ports.1),
        },
        first_packet,
    })
}

/// Judge a flow and turn the verdict into the kernel's answer for every
/// packet of it: sing-tun's `applyVerdict` on its nftables path.
pub fn decide(
    handler: &dyn SessionHandler,
    flow: &FlowInfo,
    first_packet: &[u8],
    marks: Marks,
) -> QueueDecision {
    let tcp = flow.network == Network::Tcp;
    // A panicking host must not take a worker down with it; the flow
    // takes the default path, where the stack judges it again.
    let verdict = catch_unwind(AssertUnwindSafe(|| handler.judge_flow(flow, first_packet)));
    match verdict {
        Ok(Verdict::Bypass) => QueueDecision::Repeat(marks.output),
        Ok(Verdict::Reject) if tcp => QueueDecision::Repeat(marks.reset),
        Ok(Verdict::Reject) => QueueDecision::Repeat(marks.input),
        Ok(Verdict::Drop) => QueueDecision::Drop,
        _ if tcp => QueueDecision::Accept,
        _ => QueueDecision::Repeat(marks.input),
    }
}

/// The nftables table name for a capture device. Interface names may
/// carry characters an nft identifier may not.
pub fn table_name(interface: &str) -> String {
    let safe: String = interface
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("vfawn_redirect_{safe}")
}

/// Render the whole table as one `nft -f` script. The script replaces
/// any table of the same name (a crashed predecessor's included), so
/// applying it is idempotent.
///
/// Both pre-match chains follow `nftablesAddPreMatchRules`: reply
/// direction out, the marks mirrored between packet and connection,
/// only the judged protocols on, only pure SYNs for TCP, a reset
/// honored, the exclusions out, then the queue.
pub fn ruleset(p: &RedirectParams<'_>) -> String {
    let table = table_name(p.interface);
    let tun = format!("\"{}\"", p.interface);
    let (input, out, reset) = (
        format!("{:#x}", p.input_mark),
        format!("{:#x}", p.output_mark),
        format!("{:#x}", p.reset_mark),
    );
    let queue = format!("counter queue num {} bypass", p.queue);
    let (ipv4, ipv6) = families(p.tun_addresses);
    // First in both chains (our addition, see the module comment): the
    // bypass mark back onto the packet, in either direction.
    let restore = format!("\t\tct mark {out} meta mark set ct mark return\n");
    // `nftablesAddPreMatchRules` up to the exclusions: reply direction
    // out, the marks mirrored, a family the capture lacks out, only the
    // judged protocols on, only pure SYNs for TCP, a reset honored.
    let mut judged = format!(
        "\t\tct direction reply return\n\
         \t\tmeta mark {out} ct mark set meta mark return\n\
         \t\tmeta mark {input} ct mark set meta mark return\n\
         \t\tct mark {input} meta mark set ct mark return\n"
    );
    if ipv4 != ipv6 {
        let disabled = if ipv4 { "ipv6" } else { "ipv4" };
        judged.push_str(&format!("\t\tmeta nfproto {disabled} return\n"));
    }
    judged.push_str(&format!(
        "\t\tmeta l4proto != {{ tcp, udp, icmp, ipv6-icmp }} return\n\
         \t\ttcp flags & (syn | ack) != syn return\n\
         \t\tmeta mark {reset} counter reject with tcp reset\n"
    ));
    // `nftablesCreateExcludeRules`: destinations outside the capture
    // range, the excluded ones, DNS in hijack mode, local destinations. Its DNS rule differs by hook: on
    // output every non-loopback query, on prerouting the queries from a
    // local source (sing-tun reads that from its local address set; the
    // fib answers the same question here, as for destinations).
    let excludes = |dns_scope: &str, prerouting: bool| {
        let mut e = String::new();
        // The interface filters, prerouting only (an output packet has
        // no incoming interface; sing-tun drops the whole output chain
        // instead, below).
        if prerouting {
            if !p.include_interface.is_empty() {
                e.push_str(&format!(
                    "\t\tiifname != {{ {} }} return\n",
                    quoted(p.include_interface)
                ));
            } else if !p.exclude_interface.is_empty() {
                e.push_str(&format!(
                    "\t\tiifname {{ {} }} return\n",
                    quoted(p.exclude_interface)
                ));
            }
        }
        let (in4, in6) = split_families(p.captured);
        if !in4.is_empty() {
            e.push_str(&format!("\t\tip daddr != {{ {} }} return\n", join(&in4)));
        }
        if !in6.is_empty() {
            e.push_str(&format!("\t\tip6 daddr != {{ {} }} return\n", join(&in6)));
        }
        let (v4, v6) = split_families(p.excluded);
        if !v4.is_empty() {
            e.push_str(&format!("\t\tip daddr {{ {} }} return\n", join(&v4)));
        }
        if !v6.is_empty() {
            e.push_str(&format!("\t\tip6 daddr {{ {} }} return\n", join(&v6)));
        }
        if p.dns_hijack {
            for (enabled, family) in [(ipv4, "ipv4"), (ipv6, "ipv6")] {
                if enabled {
                    e.push_str(&format!(
                        "\t\tmeta nfproto {family} {dns_scope} meta l4proto {{ tcp, udp }} \
                         th dport 53 counter return\n"
                    ));
                }
            }
        }
        e.push_str("\t\tfib daddr type local return\n");
        e
    };
    let queued = format!(
        "\t\tmeta l4proto {{ tcp, udp }} {queue}\n\
         \t\ticmp type echo-request icmp code 0 {queue}\n\
         \t\ticmpv6 type echo-request icmpv6 code 0 {queue}\n\t}}\n"
    );

    let mut s = String::new();
    s.push_str(&format!(
        "table inet {table} {{}}\ndelete table inet {table}\n"
    ));
    s.push_str(&format!("table inet {table} {{\n"));

    // Forwarded traffic, before DNAT so the original destination shows.
    s.push_str("\tchain prerouting_prematch {\n");
    s.push_str("\t\ttype filter hook prerouting priority -101; policy accept;\n");
    s.push_str(&restore);
    s.push_str(&format!("\t\tiifname {tun} return\n"));
    s.push_str(&judged);
    s.push_str(&excludes("fib saddr type local", true));
    s.push_str(&queued);

    // Local traffic. A route chain: a mark changed here re-routes.
    // sing-tun's shouldSkipOutputChain: no output chain at all when the
    // interface filters leave this host's own traffic ("lo") outside.
    let local_spared = (!p.include_interface.is_empty()
        && !p.include_interface.iter().any(|i| i == "lo"))
        || (p.include_interface.is_empty() && p.exclude_interface.iter().any(|i| i == "lo"));
    if !local_spared {
        s.push_str("\tchain output_prematch {\n");
        s.push_str("\t\ttype route hook output priority -149; policy accept;\n");
        s.push_str(&restore);
        if p.escape_mark != 0 {
            s.push_str(&format!("\t\tmeta mark {:#x} return\n", p.escape_mark));
        }
        s.push_str(&judged);
        s.push_str(&excludes("oifname != \"lo\"", false));
        // Only what the capture would put into the device is judged:
        // the capture mark routes into the device, and a flow the
        // routes spare (an excluded uid, an excluded prefix) must stay
        // spared.
        s.push_str(&format!("\t\toifname != {tun} return\n"));
        s.push_str(&queued);
    }

    // Bypassed local flows still carry the device's address.
    s.push_str("\tchain postrouting_masquerade {\n");
    s.push_str("\t\ttype nat hook postrouting priority 100; policy accept;\n");
    let (tun4, tun6) = split_families(&host_addresses(p.tun_addresses));
    if !tun4.is_empty() {
        s.push_str(&format!(
            "\t\tmeta mark {out} ip saddr {{ {} }} counter masquerade\n",
            join(&tun4)
        ));
    }
    if !tun6.is_empty() {
        s.push_str(&format!(
            "\t\tmeta mark {out} ip6 saddr {{ {} }} counter masquerade\n",
            join(&tun6)
        ));
    }
    s.push_str("\t}\n}\n");
    s
}

/// One flow waiting for its verdict.
struct Job {
    key: FlowKey,
    flow: FlowInfo,
    first_packet: Vec<u8>,
}

/// Packets queued per flow while the flow is judged: sing-tun's
/// `judging` map.
type Judging = Mutex<HashMap<FlowKey, Vec<nfq::Message>>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The installed bypass: the nft table, the queue reader, the judges.
pub struct AutoRedirect {
    table: String,
    queue: u16,
    /// sing-tun starts its Docker firewall monitor with the table.
    docker: Option<crate::linux::docker_firewall::DockerFirewall>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<nfq::Queue>>,
    workers: Vec<JoinHandle<()>>,
}

impl AutoRedirect {
    /// Bind the queue, start the reader and the judges, then install the
    /// rules. The order keeps a window without a reader from ever
    /// existing while the rules are live; the queue rule's bypass flag
    /// covers the opposite window.
    pub fn install(p: &RedirectParams<'_>, handler: Arc<dyn SessionHandler>) -> io::Result<Self> {
        let queue = open_queue(p.queue)?;
        // Verdicts must come from the socket bound to the queue; the
        // judges send theirs through a second handle on it.
        let verdicts = Arc::new(Mutex::new(nfq::Queue::from(
            queue.as_fd().try_clone_to_owned()?,
        )));
        let marks = Marks {
            input: p.input_mark,
            output: p.output_mark,
            reset: p.reset_mark,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let judging: Arc<Judging> = Arc::default();
        let (jobs, job_rx) = std::sync::mpsc::channel::<Job>();
        let job_rx = Arc::new(Mutex::new(job_rx));

        let mut installed = Self {
            table: table_name(p.interface),
            queue: p.queue,
            docker: None,
            stop: Arc::clone(&stop),
            reader: None,
            workers: Vec::new(),
        };
        // sing-tun judges each flow on a goroutine of its own; a pool
        // keeps that concurrency without a thread per flow.
        let pool = std::thread::available_parallelism().map_or(4, |n| n.get().clamp(2, 16));
        for _ in 0..pool {
            let (job_rx, judging, verdicts, handler) = (
                Arc::clone(&job_rx),
                Arc::clone(&judging),
                Arc::clone(&verdicts),
                Arc::clone(&handler),
            );
            installed.workers.push(
                std::thread::Builder::new()
                    .name("vfawn-judge".into())
                    .spawn(move || judge_loop(&job_rx, &judging, &verdicts, &*handler, marks))?,
            );
        }
        installed.reader = Some(
            std::thread::Builder::new()
                .name("vfawn-nfqueue".into())
                .spawn(move || read_loop(queue, &stop, &judging, jobs))?,
        );
        if let Err(e) = nft_script(&ruleset(p)) {
            installed.remove();
            return Err(e);
        }
        let (ipv4, ipv6) = families(p.tun_addresses);
        installed.docker = Some(crate::linux::docker_firewall::DockerFirewall::start(
            crate::linux::docker_firewall::DockerCompat::new(
                p.interface,
                &installed.table,
                ipv4,
                ipv6,
            ),
        ));
        Ok(installed)
    }

    /// Remove the rules, stop the reader and the judges, unbind the
    /// queue. Idempotent.
    pub fn remove(&mut self) {
        let _ = nft_script(&format!(
            "table inet {t} {{}}\ndelete table inet {t}\n",
            t = self.table
        ));
        // sing-tun's cleanupNFTables: the Docker rules go with the table.
        drop(self.docker.take());
        self.stop.store(true, Ordering::Release);
        // The reader drops the job channel on its way out, which is
        // what lets the judges finish.
        let queue = self.reader.take().and_then(|reader| reader.join().ok());
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        if let Some(mut queue) = queue {
            let _ = queue.unbind(self.queue);
        }
    }
}

impl Drop for AutoRedirect {
    fn drop(&mut self) {
        self.remove();
    }
}

/// A reason to expect bypassed replies to be dropped, if there is one:
/// strict reverse-path filtering consults the routing rules without the
/// restored mark unless `src_valid_mark` is on, and the capture answers
/// for every source.
pub fn rp_filter_warning(interface: &str) -> Option<String> {
    let read = |name: &str, key: &str| -> u32 {
        std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{name}/{key}"))
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    };
    let rp_filter = read("all", "rp_filter").max(read(interface, "rp_filter"));
    let valid_mark = read("all", "src_valid_mark") | read(interface, "src_valid_mark");
    (rp_filter == 1 && valid_mark == 0).then(|| {
        format!(
            "strict rp_filter on {interface} without src_valid_mark: replies of bypassed \
             connections will be dropped; set net.ipv4.conf.{interface}.src_valid_mark=1 \
             or loosen rp_filter to 2"
        )
    })
}

fn open_queue(num: u16) -> io::Result<nfq::Queue> {
    let mut queue = nfq::Queue::open()
        .map_err(|e| io::Error::new(e.kind(), format!("nfnetlink socket: {e}")))?;
    // The kernel answers EPERM both without CAP_NET_ADMIN and when
    // another process already reads this queue number.
    queue.bind(num).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("bind nfqueue {num} (taken by another process, or no CAP_NET_ADMIN): {e}"),
        )
    })?;
    queue.set_copy_range(num, COPY_RANGE)?;
    queue.set_queue_max_len(num, QUEUE_MAX_LEN)?;
    queue.set_recv_gso(num, true)?;
    socket2::SockRef::from(&queue).set_read_timeout(Some(RECV_TIMEOUT))?;
    Ok(queue)
}

/// sing-tun's `handlePacket`: never judge here, only route the packet
/// to its flow's judgement, opening one when the flow has none.
fn read_loop(
    mut queue: nfq::Queue,
    stop: &AtomicBool,
    judging: &Judging,
    jobs: Sender<Job>,
) -> nfq::Queue {
    while !stop.load(Ordering::Acquire) {
        let mut msg = match queue.recv() {
            Ok(msg) => msg,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => {
                eprintln!("vfawn: nfqueue receive failed ({e})");
                continue;
            }
        };
        let Some(job) = parse_prematch(msg.get_payload()).map(|m| Job {
            key: m.key,
            flow: m.flow,
            first_packet: m.first_packet.to_vec(),
        }) else {
            msg.set_verdict(nfq::Verdict::Accept);
            if let Err(e) = queue.verdict(msg) {
                eprintln!("vfawn: nfqueue verdict failed ({e})");
            }
            continue;
        };
        {
            let mut flows = lock(judging);
            if let Some(waiting) = flows.get_mut(&job.key) {
                waiting.push(msg);
                continue;
            }
            flows.insert(job.key, vec![msg]);
        }
        if jobs.send(job).is_err() {
            break;
        }
    }
    queue
}

/// sing-tun's `judge`: judge the flow once, then answer every packet of
/// it, including those that arrived while the judgement ran, until none
/// is left waiting.
fn judge_loop(
    jobs: &Mutex<Receiver<Job>>,
    judging: &Judging,
    verdicts: &Mutex<nfq::Queue>,
    handler: &dyn SessionHandler,
    marks: Marks,
) {
    loop {
        let Ok(job) = lock(jobs).recv() else {
            return;
        };
        let decision = decide(handler, &job.flow, &job.first_packet, marks);
        loop {
            let waiting = {
                let mut flows = lock(judging);
                let waiting = flows
                    .get_mut(&job.key)
                    .map(std::mem::take)
                    .unwrap_or_default();
                if waiting.is_empty() {
                    flows.remove(&job.key);
                }
                waiting
            };
            if waiting.is_empty() {
                break;
            }
            let mut queue = lock(verdicts);
            for mut msg in waiting {
                let verdict = match decision {
                    QueueDecision::Accept => nfq::Verdict::Accept,
                    QueueDecision::Drop => nfq::Verdict::Drop,
                    QueueDecision::Repeat(mark) => {
                        msg.set_nfmark(mark);
                        nfq::Verdict::Repeat
                    }
                };
                msg.set_verdict(verdict);
                if let Err(e) = queue.verdict(msg) {
                    eprintln!("vfawn: nfqueue verdict failed ({e})");
                }
            }
        }
    }
}

/// Feed a script to `nft -f -` as one transaction.
fn nft_script(script: &str) -> io::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::other(format!("nft exec: {e}")))?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(script.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "nft: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Which families the capture covers: sing-tun's `enableIPv4` and
/// `enableIPv6`, from the device's addresses.
fn families(tun_addresses: &[IpNet]) -> (bool, bool) {
    (
        tun_addresses.iter().any(|a| matches!(a, IpNet::V4(_))),
        tun_addresses.iter().any(|a| matches!(a, IpNet::V6(_))),
    )
}

fn host_addresses(prefixes: &[IpNet]) -> Vec<IpNet> {
    prefixes.iter().map(|p| IpNet::from(p.addr())).collect()
}

/// Split by family and merge overlaps: nft refuses overlapping
/// intervals in one set.
fn split_families(prefixes: &[IpNet]) -> (Vec<IpNet>, Vec<IpNet>) {
    let trunc: Vec<IpNet> = prefixes.iter().map(IpNet::trunc).collect();
    IpNet::aggregate(&trunc)
        .into_iter()
        .partition(|p| matches!(p, IpNet::V4(_)))
}

fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn join(prefixes: &[IpNet]) -> String {
    prefixes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfawn_core::{Action, IcmpPacket, TcpSession, UdpSession};

    const MARKS: Marks = Marks {
        input: 0x2023,
        output: 0x2024,
        reset: 0x2025,
    };

    struct Fixed(fn() -> Verdict);

    #[async_trait::async_trait]
    impl SessionHandler for Fixed {
        fn judge_flow(&self, _flow: &FlowInfo, _first: &[u8]) -> Verdict {
            (self.0)()
        }
        async fn on_tcp(&self, _session: TcpSession) {}
        async fn on_udp(&self, _session: UdpSession) {}
        async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
            Action::Drop
        }
    }

    /// 198.18.0.1 -> 93.184.216.34, an IPv4 packet around `transport`.
    fn v4(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let total = (20 + transport.len()) as u16;
        let mut p = vec![0x45, 0];
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
        p.extend_from_slice(&[198, 18, 0, 1, 93, 184, 216, 34]);
        p.extend_from_slice(transport);
        p
    }

    fn tcp(flags: u8) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&40000u16.to_be_bytes());
        t.extend_from_slice(&443u16.to_be_bytes());
        t.extend_from_slice(&[0; 8]);
        t.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        v4(6, &t)
    }

    fn udp(payload: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&40000u16.to_be_bytes());
        t.extend_from_slice(&443u16.to_be_bytes());
        t.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        t.extend_from_slice(&[0, 0]);
        t.extend_from_slice(payload);
        v4(17, &t)
    }

    fn icmp(kind: u8, code: u8) -> Vec<u8> {
        v4(1, &[kind, code, 0, 0, 0x12, 0x34, 0, 1])
    }

    fn judged(packet: &[u8], verdict: fn() -> Verdict) -> QueueDecision {
        let m = parse_prematch(packet).expect("a first packet");
        decide(&Fixed(verdict), &m.flow, m.first_packet, MARKS)
    }

    #[test]
    fn first_packets_parse_as_sing_tun_reads_them() {
        let syn = tcp(0x02);
        let m = parse_prematch(&syn).unwrap();
        assert_eq!(m.flow.network, Network::Tcp);
        assert_eq!(m.flow.destination, "93.184.216.34:443".parse().unwrap());
        assert!(m.first_packet.is_empty());
        // Only a pure SYN starts a TCP flow.
        assert!(parse_prematch(&tcp(0x12)).is_none());
        assert!(parse_prematch(&tcp(0x10)).is_none());

        // UDP hands its payload over.
        let datagram = udp(b"quic initial");
        let m = parse_prematch(&datagram).unwrap();
        assert_eq!(m.flow.network, Network::Udp);
        assert_eq!(m.first_packet, b"quic initial");

        // ICMP: echo requests only; the identifier keys the flow, the
        // flow itself carries no ports, as the stack's does.
        let echo = icmp(8, 0);
        let m = parse_prematch(&echo).unwrap();
        assert_eq!(m.flow.network, Network::Icmp);
        assert_eq!(m.key.destination.port(), 0x1234);
        assert_eq!(m.flow.destination.port(), 0);
        assert!(parse_prematch(&icmp(0, 0)).is_none());
        assert!(parse_prematch(&icmp(8, 1)).is_none());

        // Strangers and garbage.
        assert!(parse_prematch(&v4(47, &[0; 8])).is_none());
        assert!(parse_prematch(&[0x45, 0]).is_none());
        assert!(parse_prematch(&[]).is_none());
    }

    #[test]
    fn verdicts_map_as_apply_verdict_does() {
        let (syn, datagram, echo) = (tcp(0x02), udp(b"x"), icmp(8, 0));
        // Bypass and Drop are the same for every protocol.
        for p in [&syn, &datagram, &echo] {
            assert_eq!(judged(p, || Verdict::Bypass), QueueDecision::Repeat(0x2024));
            assert_eq!(judged(p, || Verdict::Drop), QueueDecision::Drop);
        }
        // TCP: reset mark for Reject, unmarked for the rest.
        assert_eq!(
            judged(&syn, || Verdict::Reject),
            QueueDecision::Repeat(0x2025)
        );
        assert_eq!(judged(&syn, || Verdict::Accept), QueueDecision::Accept);
        // Datagrams: everything else rides the capture mark.
        for p in [&datagram, &echo] {
            assert_eq!(judged(p, || Verdict::Reject), QueueDecision::Repeat(0x2023));
            assert_eq!(judged(p, || Verdict::Accept), QueueDecision::Repeat(0x2023));
        }
        // A panicking host takes the default path.
        assert_eq!(judged(&syn, || panic!("host bug")), QueueDecision::Accept);
        assert_eq!(
            judged(&datagram, || panic!("host bug")),
            QueueDecision::Repeat(0x2023)
        );
    }

    #[test]
    fn table_names_are_nft_identifiers() {
        assert_eq!(table_name("tun0"), "vfawn_redirect_tun0");
        assert_eq!(table_name("utun-3.x"), "vfawn_redirect_utun_3_x");
    }

    fn params() -> RedirectParams<'static> {
        RedirectParams {
            interface: "tun0",
            tun_addresses: Box::leak(Box::new(["198.18.0.1/15".parse().unwrap()])),
            captured: Box::leak(Box::new([
                "198.51.100.0/24".parse().unwrap(),
                "203.0.113.0/24".parse().unwrap(),
            ])),
            excluded: Box::leak(Box::new([
                "10.0.0.0/8".parse().unwrap(),
                "10.1.0.0/16".parse().unwrap(),
                "fe80::/10".parse().unwrap(),
            ])),
            include_interface: &[],
            exclude_interface: &[],
            escape_mark: 0x2022,
            dns_hijack: true,
            input_mark: 0x2023,
            output_mark: 0x2024,
            reset_mark: 0x2025,
            queue: 100,
        }
    }

    #[test]
    fn the_ruleset_follows_the_pre_match_order() {
        let s = ruleset(&params());
        assert!(s.starts_with("table inet vfawn_redirect_tun0 {}\ndelete table"));
        for chain in ["chain prerouting_prematch", "chain output_prematch"] {
            let body = &s[s.find(chain).unwrap()..];
            let body = &body[..body.find("\n\t}").unwrap()];
            let rules: Vec<&str> = body.lines().skip(2).map(str::trim).collect();
            // Every later packet of a bypassed flow stops at the first.
            assert_eq!(rules[0], "ct mark 0x2024 meta mark set ct mark return");
            let pos = |n: &str| {
                rules
                    .iter()
                    .position(|r| r.starts_with(n))
                    .unwrap_or_else(|| panic!("{chain}: {n}"))
            };
            // nftablesAddPreMatchRules, in order.
            let order = [
                "ct direction reply return",
                "meta mark 0x2024 ct mark set meta mark return",
                "meta mark 0x2023 ct mark set meta mark return",
                "ct mark 0x2023 meta mark set ct mark return",
                // An IPv4-only capture leaves IPv6 alone.
                "meta nfproto ipv6 return",
                "meta l4proto != { tcp, udp, icmp, ipv6-icmp } return",
                "tcp flags & (syn | ack) != syn return",
                "meta mark 0x2025 counter reject with tcp reset",
                "ip daddr != { 198.51.100.0/24, 203.0.113.0/24 } return",
                "ip daddr { 10.0.0.0/8 } return",
                "meta nfproto ipv4 ",
                "fib daddr type local return",
                "meta l4proto { tcp, udp } counter queue num 100 bypass",
                "icmp type echo-request icmp code 0 counter queue num 100 bypass",
                "icmpv6 type echo-request icmpv6 code 0 counter queue num 100 bypass",
            ];
            let positions: Vec<usize> = order.iter().map(|n| pos(n)).collect();
            assert!(positions.is_sorted(), "{chain}: {rules:#?}");
            // The capture mark is never restored before the reply
            // direction leaves: a reply from the device carrying it
            // would be routed straight back in.
            assert!(pos("ct direction reply return") < pos("ct mark 0x2023"));
        }
        assert!(s.contains("type route hook output priority -149"));
        assert!(s.contains("type filter hook prerouting priority -101"));
        assert!(s.contains("meta mark 0x2022 return"));
        assert!(s.contains("oifname != \"tun0\" return"));
        assert!(s.contains("ip daddr { 10.0.0.0/8 } return"));
        assert!(s.contains("ip6 daddr { fe80::/10 } return"));
        assert!(s.contains("meta mark 0x2024 ip saddr { 198.18.0.1/32 } counter masquerade"));
        assert!(!s.contains("ip6 saddr"));
        // DNS in hijack mode is never judged: every non-loopback query
        // from this host, the queries from a local source on prerouting.
        assert!(s.contains(
            "meta nfproto ipv4 oifname != \"lo\" meta l4proto { tcp, udp } th dport 53 counter return"
        ));
        assert!(s.contains(
            "meta nfproto ipv4 fib saddr type local meta l4proto { tcp, udp } th dport 53 counter return"
        ));
        assert!(
            !s.contains("meta nfproto ipv6 oifname"),
            "no IPv6 in the capture"
        );
    }

    #[test]
    fn interface_filters_follow_sing_tun() {
        let lan: &'static [String] = Box::leak(Box::new(["br-lan".to_string()]));
        let with_lo: &'static [String] =
            Box::leak(Box::new(["lo".to_string(), "br-lan".to_string()]));
        let lo: &'static [String] = Box::leak(Box::new(["lo".to_string()]));

        // Include without "lo": forwarded traffic filtered, and no
        // output chain (this host's traffic is not captured).
        let mut p = params();
        p.include_interface = lan;
        let s = ruleset(&p);
        let pre = &s[s.find("chain prerouting_prematch").unwrap()..];
        assert!(pre.contains("iifname != { \"br-lan\" } return"));
        assert!(!s.contains("chain output_prematch"));

        // Include with "lo": both chains.
        p.include_interface = with_lo;
        let s = ruleset(&p);
        assert!(s.contains("iifname != { \"lo\", \"br-lan\" } return"));
        assert!(s.contains("chain output_prematch"));

        // Exclude: forwarded traffic from it spared; excluding "lo"
        // drops the output chain.
        let mut p = params();
        p.exclude_interface = lan;
        let s = ruleset(&p);
        assert!(s.contains("iifname { \"br-lan\" } return"));
        assert!(s.contains("chain output_prematch"));
        p.exclude_interface = lo;
        assert!(!ruleset(&p).contains("chain output_prematch"));

        // Include wins over exclude.
        p.include_interface = with_lo;
        p.exclude_interface = lan;
        let s = ruleset(&p);
        assert!(!s.contains("iifname { \"br-lan\" } return"));
        assert!(s.contains("chain output_prematch"));
    }

    #[test]
    fn no_escape_mark_no_escape_rule() {
        let mut p = params();
        p.escape_mark = 0;
        p.excluded = &[];
        p.captured = &[];
        p.dns_hijack = false;
        let s = ruleset(&p);
        assert!(
            !s.contains("daddr !="),
            "an unbounded capture judges every destination"
        );
        assert!(!s.contains("meta mark 0x0 return"));
        assert!(!s.contains("ip daddr {"));
        assert!(!s.contains("th dport 53"), "DNS judged when not hijacked");
        // Both families in the capture: neither is skipped.
        p.tun_addresses = Box::leak(Box::new([
            "198.18.0.1/15".parse().unwrap(),
            "fdfe:dcba:9876::1/126".parse().unwrap(),
        ]));
        assert!(!ruleset(&p).contains("meta nfproto ipv6 return"));
    }
}
