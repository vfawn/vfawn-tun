// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Docker compatibility for the auto-redirect capture, after sing-tun's
//! `redirect_nftables_docker.go` (origin/dev 79ed065).
//!
//! Docker's iptables-nft rules give the `filter` table's forward path a
//! dropping policy, so traffic forwarded into or out of the device dies
//! there. The `DOCKER-USER` chain is Docker's documented place for user
//! exceptions: two rules at its head accept everything leaving into and
//! arriving from the device, each tagged with a comment that names our
//! table.
//!
//! Docker rebuilds its tables whenever it restarts, so the rules are
//! kept by a ruleset monitor. Each generation (one nftables batch) that
//! touched an `ip`/`ip6` `filter` table, its `DOCKER-USER` chain or a
//! rule in that chain triggers a reconcile: keep one rule per
//! direction, delete any other rule carrying our comment prefix, insert
//! what is missing. Without Docker (no such table or chain), nothing is
//! touched.
//!
//! Mapped onto this crate's nft-CLI backend: the monitor is
//! `nft monitor` (its `# new generation` lines are the batch
//! boundaries the netlink monitor reports), rules are read through
//! `nft -j -a list chain` and changed in one `nft -f` batch.

use serde_json::Value;
use std::io::{self, BufRead, BufReader, Write as _};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;

const DOCKER_TABLE: &str = "filter";
const DOCKER_USER_CHAIN: &str = "DOCKER-USER";

/// Which way a compatibility rule faces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// `oifname <device> accept`.
    Output,
    /// `iifname <device> accept`.
    Input,
}

impl Direction {
    fn key(self) -> &'static str {
        match self {
            Self::Output => "oifname",
            Self::Input => "iifname",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Output => "output to tun",
            Self::Input => "input from tun",
        }
    }
}

/// What the rules are about: the device, the owning table's name (the
/// comment prefix), the families the capture covers.
#[derive(Debug, Clone)]
pub struct DockerCompat {
    interface: String,
    prefix: String,
    families: Vec<&'static str>,
}

impl DockerCompat {
    pub fn new(interface: &str, table: &str, ipv4: bool, ipv6: bool) -> Self {
        let mut families = Vec::new();
        if ipv4 {
            families.push("ip");
        }
        if ipv6 {
            families.push("ip6");
        }
        Self {
            interface: interface.to_string(),
            prefix: format!("!{table}: Docker compatibility "),
            families,
        }
    }

    fn comment(&self, direction: Direction) -> String {
        format!("{}{}", self.prefix, direction.label())
    }

    /// The `nft -f` batch that brings one family's `DOCKER-USER` chain
    /// to the desired state, given its rules as `nft -j -a list chain`
    /// prints them; `None` when nothing needs to change. sing-tun's
    /// `reconcileDockerFirewallRules`, or with `cleanup` its
    /// `cleanupDockerFirewallRules`.
    fn plan(&self, family: &str, listing: &str, cleanup: bool) -> Option<String> {
        let rules = chain_rules(listing);
        let chain = format!("{family} {DOCKER_TABLE} {DOCKER_USER_CHAIN}");
        let mut script = String::new();
        let (mut has_output, mut has_input) = (cleanup, cleanup);
        for rule in &rules {
            let Some(comment) = rule.get("comment").and_then(Value::as_str) else {
                continue;
            };
            let handle = rule.get("handle").and_then(Value::as_u64).unwrap_or(0);
            if !cleanup && !has_output && self.matches(rule, comment, Direction::Output) {
                has_output = true;
            } else if !cleanup && !has_input && self.matches(rule, comment, Direction::Input) {
                has_input = true;
            } else if comment.starts_with(&self.prefix) {
                script.push_str(&format!("delete rule {chain} handle {handle}\n"));
            }
        }
        // Inserted at the head, output first, as sing-tun inserts them.
        for (missing, direction) in [
            (!has_output, Direction::Output),
            (!has_input, Direction::Input),
        ] {
            if missing {
                script.push_str(&format!(
                    "insert rule {chain} {} \"{}\" counter accept comment \"{}\"\n",
                    direction.key(),
                    self.interface,
                    self.comment(direction)
                ));
            }
        }
        (!script.is_empty()).then_some(script)
    }

    /// sing-tun's `nftablesDockerCompatibilityRuleMatches`: our comment
    /// for this direction, and exactly `<key> == <device>`, a counter,
    /// accept.
    fn matches(&self, rule: &Value, comment: &str, direction: Direction) -> bool {
        if comment != self.comment(direction) {
            return false;
        }
        let Some(exprs) = rule.get("expr").and_then(Value::as_array) else {
            return false;
        };
        let [matched, counter, verdict] = exprs.as_slice() else {
            return false;
        };
        let matched = &matched["match"];
        matched["op"] == "=="
            && matched["left"]["meta"]["key"] == direction.key()
            && matched["right"] == self.interface.as_str()
            && counter.get("counter").is_some()
            && verdict.get("accept").is_some()
    }

    /// Reconcile (or with `cleanup`, remove) the rules in every family
    /// that has Docker's chain: sing-tun's `configureDockerFirewall`.
    pub fn configure(&self, cleanup: bool) -> io::Result<()> {
        let mut result = Ok(());
        for family in &self.families {
            let Some(listing) = list_docker_chain(family) else {
                continue;
            };
            if let Some(script) = self.plan(family, &listing, cleanup)
                && let Err(e) = nft_batch(&script)
            {
                result = Err(e);
            }
        }
        result
    }
}

/// The rules of a chain listing, in order.
fn chain_rules(listing: &str) -> Vec<Value> {
    let Ok(document) = serde_json::from_str::<Value>(listing) else {
        return Vec::new();
    };
    document["nftables"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.get("rule").cloned())
                .collect()
        })
        .unwrap_or_default()
}

/// Docker's user chain in one family, listed with handles; `None` when
/// the table or the chain does not exist (no Docker, or a Docker on the
/// legacy iptables backend nft cannot see).
fn list_docker_chain(family: &str) -> Option<String> {
    let output = Command::new("nft")
        .args([
            "-j",
            "-a",
            "list",
            "chain",
            family,
            DOCKER_TABLE,
            DOCKER_USER_CHAIN,
        ])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn nft_batch(script: &str) -> io::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(script.as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "nft: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// sing-tun's `nftablesDockerFirewallEventRelevant` over one line of
/// `nft monitor`: a table event for an `ip`/`ip6` `filter` table, a
/// chain event for its `DOCKER-USER` chain, a rule event in that chain.
pub fn event_relevant(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    let [action, object, family, table, rest @ ..] = words.as_slice() else {
        return false;
    };
    let docker_table =
        matches!(*family, "ip" | "ip6") && *table == DOCKER_TABLE && !action.starts_with('#');
    match *object {
        "table" => docker_table,
        "chain" | "rule" => docker_table && rest.first() == Some(&DOCKER_USER_CHAIN),
        _ => false,
    }
}

/// The running monitor: `nft monitor` and the thread reading it.
pub struct DockerFirewall {
    compat: DockerCompat,
    monitor: Option<(Child, JoinHandle<()>)>,
    active: bool,
}

impl DockerFirewall {
    /// Start the monitor, then reconcile once (sing-tun's order: no
    /// change can slip between the two). Failures are reported, never
    /// fatal: the capture works without Docker compatibility.
    pub fn start(compat: DockerCompat) -> Self {
        let monitor = match spawn_monitor(compat.clone()) {
            Ok(monitor) => Some(monitor),
            Err(e) => {
                eprintln!("vfawn: start nftables monitor: {e}");
                None
            }
        };
        if let Err(e) = compat.configure(false) {
            eprintln!("vfawn: configure docker firewall: {e}");
        }
        Self {
            compat,
            monitor,
            active: true,
        }
    }

    /// Stop the monitor, then remove the rules — in that order, or the
    /// monitor would answer the removal by putting them back.
    /// Idempotent.
    pub fn stop(&mut self) {
        if let Some((mut child, reader)) = self.monitor.take() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
        }
        if std::mem::take(&mut self.active)
            && let Err(e) = self.compat.configure(true)
        {
            eprintln!("vfawn: cleanup docker firewall: {e}");
        }
    }
}

impl Drop for DockerFirewall {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_monitor(compat: DockerCompat) -> io::Result<(Child, JoinHandle<()>)> {
    let mut child = Command::new("nft")
        .arg("monitor")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().expect("stdout piped");
    let reader = std::thread::Builder::new()
        .name("vfawn-nftmon".into())
        .spawn(move || {
            // One reconcile per generation that touched Docker's chain.
            let mut relevant = false;
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if line.starts_with("# new generation") {
                    if std::mem::take(&mut relevant)
                        && let Err(e) = compat.configure(false)
                    {
                        eprintln!("vfawn: update docker firewall: {e}");
                    }
                } else if event_relevant(&line) {
                    relevant = true;
                }
            }
        });
    match reader {
        Ok(reader) => Ok((child, reader)),
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compat() -> DockerCompat {
        DockerCompat::new("vfawn56", "vfawn_redirect_vfawn56", true, false)
    }

    fn listing(rules: &[&str]) -> String {
        let mut items = vec![r#"{"metainfo": {"version": "1.0.6"}}"#.to_string()];
        items.push(
            r#"{"chain": {"family": "ip", "table": "filter", "name": "DOCKER-USER", "handle": 1}}"#
                .to_string(),
        );
        items.extend(rules.iter().map(|r| format!(r#"{{"rule": {r}}}"#)));
        format!(r#"{{"nftables": [{}]}}"#, items.join(", "))
    }

    fn ours(key: &str, label: &str, handle: u32) -> String {
        format!(
            r#"{{"family": "ip", "table": "filter", "chain": "DOCKER-USER", "handle": {handle},
            "comment": "!vfawn_redirect_vfawn56: Docker compatibility {label}",
            "expr": [{{"match": {{"op": "==", "left": {{"meta": {{"key": "{key}"}}}}, "right": "vfawn56"}}}},
                     {{"counter": {{"packets": 0, "bytes": 0}}}}, {{"accept": null}}]}}"#
        )
    }

    const FOREIGN: &str = r#"{"family": "ip", "table": "filter", "chain": "DOCKER-USER", "handle": 2,
        "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"return": null}]}"#;

    #[test]
    fn an_empty_chain_gets_both_rules() {
        let script = compat().plan("ip", &listing(&[FOREIGN]), false).unwrap();
        assert_eq!(
            script,
            "insert rule ip filter DOCKER-USER oifname \"vfawn56\" counter accept comment \
             \"!vfawn_redirect_vfawn56: Docker compatibility output to tun\"\n\
             insert rule ip filter DOCKER-USER iifname \"vfawn56\" counter accept comment \
             \"!vfawn_redirect_vfawn56: Docker compatibility input from tun\"\n"
        );
    }

    #[test]
    fn a_complete_chain_is_left_alone_and_duplicates_go() {
        let (out, inp) = (
            ours("oifname", "output to tun", 5),
            ours("iifname", "input from tun", 6),
        );
        assert!(
            compat()
                .plan("ip", &listing(&[&out, &inp, FOREIGN]), false)
                .is_none()
        );

        // A second copy, or one of ours that no longer matches (another
        // device), is deleted; the foreign rule never is.
        let dup = ours("oifname", "output to tun", 7);
        let stale = ours("oifname", "output to tun", 8).replace("\"vfawn56\"}", "\"old0\"}");
        let script = compat()
            .plan("ip", &listing(&[&out, &inp, &dup, &stale, FOREIGN]), false)
            .unwrap();
        assert_eq!(
            script,
            "delete rule ip filter DOCKER-USER handle 7\n\
             delete rule ip filter DOCKER-USER handle 8\n"
        );
    }

    #[test]
    fn cleanup_removes_only_ours() {
        let (out, inp) = (
            ours("oifname", "output to tun", 5),
            ours("iifname", "input from tun", 6),
        );
        let script = compat()
            .plan("ip", &listing(&[&out, FOREIGN, &inp]), true)
            .unwrap();
        assert_eq!(
            script,
            "delete rule ip filter DOCKER-USER handle 5\n\
             delete rule ip filter DOCKER-USER handle 6\n"
        );
        assert!(compat().plan("ip", &listing(&[FOREIGN]), true).is_none());
    }

    #[test]
    fn only_docker_events_are_relevant() {
        for line in [
            "add table ip filter",
            "delete table ip6 filter",
            "add chain ip filter DOCKER-USER",
            "delete rule ip filter DOCKER-USER handle 2",
            "add rule ip filter DOCKER-USER counter packets 0 bytes 0 return",
        ] {
            assert!(event_relevant(line), "{line}");
        }
        for line in [
            "add table inet filter",
            "add table ip nat",
            "add chain ip filter FORWARD",
            "add rule ip filter FORWARD counter accept",
            "add rule inet vfawn_redirect_vfawn56 output_prematch meta mark 0x2022 return",
            "# new generation 4 by process 26564 (nft)",
            "add set ip filter s { type ipv4_addr; }",
            "",
        ] {
            assert!(!event_relevant(line), "{line}");
        }
    }

    #[test]
    fn families_follow_the_capture() {
        assert_eq!(compat().families, ["ip"]);
        assert_eq!(
            DockerCompat::new("t", "x", true, true).families,
            ["ip", "ip6"]
        );
    }
}
