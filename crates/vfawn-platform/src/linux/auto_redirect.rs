// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Per-flow kernel bypass: judge a TCP connection on its SYN, before
//! the packet reaches the device.
//!
//! Netfilter queues each new connection's pure SYN to this process;
//! `judge_flow` answers, and the answer becomes the connection's fate:
//!
//! * `Bypass` — the SYN re-enters its chain carrying the bypass mark,
//!   the mark is mirrored into conntrack, and every later packet of the
//!   connection picks it back up. A policy rule (planned by the route
//!   engine) sends marked traffic to the main table, so the connection
//!   never touches the device or the stack.
//! * `Reject` — the SYN re-enters carrying the reset mark, which a rule
//!   turns into a TCP reset.
//! * `Drop` — discarded.
//! * anything else — accepted unmarked: the capture routes it into the
//!   device as before and the stack judges it again.
//!
//! Two consequences of a capture that routes into the device by default
//! (rather than one that marks its way in) shape the rules:
//!
//! * A local socket picks its source address when it connects, from the
//!   route it saw then — the device's. Re-routing to the main table does
//!   not rewrite it, so bypassed local connections are masqueraded.
//! * Replies of a bypassed forwarded connection would be captured too,
//!   so the mark is restored on the reply direction as well.
//!
//! The rules live in a table of their own (`vfawn_redirect_<if>`),
//! installed and removed in one `nft -f` transaction. The `vfawn_`
//! prefix puts it in the crash-safety scanner's sweep.

use ipnet::IpNet;
use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;
use vfawn_core::{FlowInfo, Network, SessionHandler, Verdict};
use vfawn_wire::IpProtocol;

/// How long the queue reader blocks before it rechecks the stop flag.
const RECV_TIMEOUT: Duration = Duration::from_millis(200);
/// Kernel-side queue depth. Past it, fail-open accepts the SYN, which
/// leaves the connection on the captured path — degraded, not broken.
const QUEUE_MAX_LEN: u32 = 4096;
/// Bytes copied per queued packet: a SYN with every IPv6 extension
/// header the parser walks fits with room to spare.
const COPY_RANGE: u16 = 512;

/// Everything the rules and the reader need.
#[derive(Debug, Clone)]
pub struct RedirectParams<'a> {
    /// The capture device.
    pub interface: &'a str,
    /// The device's own addresses: the source a bypassed local
    /// connection carries until masquerade rewrites it.
    pub tun_addresses: &'a [IpNet],
    /// Destinations the capture already spares; never queued.
    pub excluded: &'a [IpNet],
    /// This process's own socket mark; zero when unused.
    pub escape_mark: u32,
    pub output_mark: u32,
    pub reset_mark: u32,
    pub queue: u16,
}

/// What the reader tells the kernel about one queued SYN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueDecision {
    /// Continue unmarked.
    Accept,
    /// Discard.
    Drop,
    /// Re-enter the chain carrying this mark.
    Repeat(u32),
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
pub fn ruleset(p: &RedirectParams<'_>) -> String {
    let table = table_name(p.interface);
    let tun = format!("\"{}\"", p.interface);
    let out = format!("{:#x}", p.output_mark);
    let reset = format!("{:#x}", p.reset_mark);
    let queue = format!("counter queue num {} bypass", p.queue);
    // First in both chains, because every packet of a bypassed
    // connection after its SYN stops here: the connection's mark back
    // onto the packet, in either direction. The reply direction is not
    // optional: a capture that routes everything into the device would
    // take a bypassed forwarded connection's replies too, and strict
    // reverse-path filtering consults the routing rules with this mark.
    let restore = format!("\t\tct mark {out} meta mark set ct mark return\n");
    // Shared by both hooks, past their own early-outs: a judged SYN
    // writes its mark into the connection, then only fresh SYNs go on,
    // and a reset verdict is honored.
    let judged = format!(
        "\t\tmeta mark {out} ct mark set meta mark return\n\
         \t\tmeta l4proto != tcp return\n\
         \t\ttcp flags & (syn | ack) != syn return\n\
         \t\tmeta mark {reset} counter reject with tcp reset\n"
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
    s.push_str("\t\tct direction reply return\n");
    s.push_str(&judged);
    s.push_str("\t\tfib daddr type { local, broadcast, multicast } return\n");
    let (v4, v6) = split_families(p.excluded);
    if !v4.is_empty() {
        s.push_str(&format!("\t\tip daddr {{ {} }} return\n", join(&v4)));
    }
    if !v6.is_empty() {
        s.push_str(&format!("\t\tip6 daddr {{ {} }} return\n", join(&v6)));
    }
    s.push_str(&format!("\t\t{queue}\n\t}}\n"));

    // Local traffic. A route chain: a mark changed here re-routes.
    s.push_str("\tchain output_prematch {\n");
    s.push_str("\t\ttype route hook output priority -149; policy accept;\n");
    s.push_str(&restore);
    if p.escape_mark != 0 {
        s.push_str(&format!("\t\tmeta mark {:#x} return\n", p.escape_mark));
    }
    s.push_str("\t\tct direction reply return\n");
    s.push_str(&judged);
    // Only what the capture would put into the device is worth judging.
    s.push_str(&format!("\t\toifname != {tun} return\n"));
    s.push_str(&format!("\t\t{queue}\n\t}}\n"));

    // Bypassed local connections still carry the device's address.
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

/// Turn one queued packet into a decision. Anything that does not
/// parse as a TCP packet is accepted untouched: the queue rule only
/// sends SYNs, and a stranger is better left on its normal path.
pub fn decide(
    handler: &dyn SessionHandler,
    packet: &[u8],
    output_mark: u32,
    reset_mark: u32,
) -> QueueDecision {
    let Some(key) = vfawn_wire::flow_key(packet) else {
        return QueueDecision::Accept;
    };
    if key.protocol != IpProtocol::Tcp {
        return QueueDecision::Accept;
    }
    let flow = FlowInfo {
        network: Network::Tcp,
        source: SocketAddr::new(key.src, key.src_port),
        destination: SocketAddr::new(key.dst, key.dst_port),
    };
    // A panicking host must not take the reader down with it: the
    // queue would fill and every new connection would wait on it.
    match catch_unwind(AssertUnwindSafe(|| handler.judge_flow(&flow, &[]))) {
        Ok(Verdict::Bypass) => QueueDecision::Repeat(output_mark),
        Ok(Verdict::Reject) => QueueDecision::Repeat(reset_mark),
        Ok(Verdict::Drop) => QueueDecision::Drop,
        _ => QueueDecision::Accept,
    }
}

/// The installed bypass: the nft table and the queue reader.
pub struct AutoRedirect {
    table: String,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl AutoRedirect {
    /// Bind the queue, start the reader, then install the rules. The
    /// order keeps a window without a reader from ever existing while
    /// the rules are live; the queue rule's bypass flag covers the
    /// opposite window.
    pub fn install(p: &RedirectParams<'_>, handler: Arc<dyn SessionHandler>) -> io::Result<Self> {
        let mut queue = open_queue(p.queue)?;
        let stop = Arc::new(AtomicBool::new(false));
        let (num, output_mark, reset_mark) = (p.queue, p.output_mark, p.reset_mark);
        let reader = {
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("vfawn-nfqueue".into())
                .spawn(move || {
                    read_loop(&mut queue, &stop, &*handler, output_mark, reset_mark);
                    let _ = queue.unbind(num);
                })?
        };
        let mut installed = Self {
            table: table_name(p.interface),
            stop,
            reader: Some(reader),
        };
        if let Err(e) = nft_script(&ruleset(p)) {
            installed.remove();
            return Err(e);
        }
        Ok(installed)
    }

    /// Remove the rules, then stop the reader. Idempotent.
    pub fn remove(&mut self) {
        let _ = nft_script(&format!(
            "table inet {t} {{}}\ndelete table inet {t}\n",
            t = self.table
        ));
        self.stop.store(true, Ordering::Release);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
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
    queue.set_fail_open(num, true)?;
    queue.set_recv_gso(num, true)?;
    socket2::SockRef::from(&queue).set_read_timeout(Some(RECV_TIMEOUT))?;
    Ok(queue)
}

fn read_loop(
    queue: &mut nfq::Queue,
    stop: &AtomicBool,
    handler: &dyn SessionHandler,
    output_mark: u32,
    reset_mark: u32,
) {
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
        let verdict = match decide(handler, msg.get_payload(), output_mark, reset_mark) {
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

    struct Fixed(fn() -> Verdict);

    #[async_trait::async_trait]
    impl SessionHandler for Fixed {
        fn judge_flow(&self, flow: &FlowInfo, _first: &[u8]) -> Verdict {
            assert_eq!(flow.network, Network::Tcp);
            assert_eq!(flow.destination, "93.184.216.34:443".parse().unwrap());
            (self.0)()
        }
        async fn on_tcp(&self, _session: TcpSession) {}
        async fn on_udp(&self, _session: UdpSession) {}
        async fn on_icmp(&self, _packet: IcmpPacket) -> Action {
            Action::Drop
        }
    }

    /// 198.18.0.1:40000 -> 93.184.216.34:443, the given protocol, the
    /// given TCP flags.
    fn packet(protocol: u8, flags: u8) -> Vec<u8> {
        let mut p = vec![
            0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, protocol, 0, 0, 198, 18, 0, 1, 93, 184, 216, 34,
        ];
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&[0; 8]);
        p.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        p
    }

    fn params() -> RedirectParams<'static> {
        RedirectParams {
            interface: "tun0",
            tun_addresses: Box::leak(Box::new(["198.18.0.1/15".parse().unwrap()])),
            excluded: Box::leak(Box::new([
                "10.0.0.0/8".parse().unwrap(),
                "10.1.0.0/16".parse().unwrap(),
                "fe80::/10".parse().unwrap(),
            ])),
            escape_mark: 0x2022,
            output_mark: 0x2024,
            reset_mark: 0x2025,
            queue: 100,
        }
    }

    #[test]
    fn verdicts_map_onto_queue_decisions() {
        let syn = packet(6, 0x02);
        let cases: [(fn() -> Verdict, QueueDecision); 5] = [
            (|| Verdict::Bypass, QueueDecision::Repeat(0x2024)),
            (|| Verdict::Reject, QueueDecision::Repeat(0x2025)),
            (|| Verdict::Drop, QueueDecision::Drop),
            (|| Verdict::Accept, QueueDecision::Accept),
            (
                || Verdict::Redirect("1.1.1.1:443".parse().unwrap()),
                QueueDecision::Accept,
            ),
        ];
        for (verdict, expected) in cases {
            assert_eq!(decide(&Fixed(verdict), &syn, 0x2024, 0x2025), expected);
        }
    }

    #[test]
    fn strangers_and_panics_are_accepted() {
        let bypass = Fixed(|| Verdict::Bypass);
        assert_eq!(
            decide(&bypass, &packet(17, 0), 0x2024, 0x2025),
            QueueDecision::Accept
        );
        assert_eq!(
            decide(&bypass, &[0x45, 0], 0x2024, 0x2025),
            QueueDecision::Accept
        );
        assert_eq!(decide(&bypass, &[], 0x2024, 0x2025), QueueDecision::Accept);
        let panics = Fixed(|| panic!("host bug"));
        assert_eq!(
            decide(&panics, &packet(6, 0x02), 0x2024, 0x2025),
            QueueDecision::Accept
        );
    }

    #[test]
    fn table_names_are_nft_identifiers() {
        assert_eq!(table_name("tun0"), "vfawn_redirect_tun0");
        assert_eq!(table_name("utun-3.x"), "vfawn_redirect_utun_3_x");
    }

    #[test]
    fn the_ruleset_mirrors_before_it_queues() {
        let s = ruleset(&params());
        let at = |needle: &str| {
            s.find(needle)
                .unwrap_or_else(|| panic!("missing {needle:?} in\n{s}"))
        };
        // The script replaces any predecessor in one transaction.
        assert!(s.starts_with("table inet vfawn_redirect_tun0 {}\ndelete table"));
        // Both hooks restore first (every later packet of a bypassed
        // connection, either direction, stops there), mirror, filter
        // to pure SYNs, then queue.
        for chain in ["chain prerouting_prematch", "chain output_prematch"] {
            let body = &s[at(chain)..];
            let body = &body[..body.find("\n\t}").unwrap()];
            let rules: Vec<&str> = body.lines().skip(2).map(str::trim).collect();
            assert_eq!(
                rules[0], "ct mark 0x2024 meta mark set ct mark return",
                "{chain}"
            );
            assert!(!body.contains("ct direction reply ct mark"));
            let pos = |n: &str| body.find(n).unwrap_or_else(|| panic!("{chain}: {n}"));
            assert!(pos("ct direction reply return") < pos("queue num 100"));
            assert!(pos("meta mark 0x2024 ct mark set meta mark return") < pos("queue num 100"));
            assert!(pos("ct mark 0x2024 meta mark set ct mark return") < pos("queue num 100"));
            assert!(pos("tcp flags & (syn | ack) != syn return") < pos("queue num 100"));
            assert!(pos("meta mark 0x2025 counter reject with tcp reset") < pos("queue num 100"));
            assert!(body.contains("queue num 100 bypass"));
        }
        assert!(s.contains("type route hook output priority -149"));
        assert!(s.contains("type filter hook prerouting priority -101"));
        assert!(s.contains("meta mark 0x2022 return"));
        assert!(s.contains("oifname != \"tun0\" return"));
        // Overlaps merged, families split.
        assert!(s.contains("ip daddr { 10.0.0.0/8 } return"));
        assert!(s.contains("ip6 daddr { fe80::/10 } return"));
        // Masquerade keys on the device's host address, not its prefix.
        assert!(s.contains("meta mark 0x2024 ip saddr { 198.18.0.1/32 } counter masquerade"));
        assert!(!s.contains("ip6 saddr"));
    }

    #[test]
    fn no_escape_mark_no_escape_rule() {
        let mut p = params();
        p.escape_mark = 0;
        p.excluded = &[];
        let s = ruleset(&p);
        assert!(!s.contains("meta mark 0x0 return"));
        assert!(!s.contains("ip daddr {"));
    }
}
