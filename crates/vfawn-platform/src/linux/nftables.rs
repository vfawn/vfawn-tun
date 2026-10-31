// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Linux nftables rules backend.
//!
//! rtnetlink handles routing tables and address/prefix policy rules; this
//! backend handles what rtnetlink cannot express: destination-port
//! matching (the DNS leak-prevention rule) and per-rule comments (the
//! instance tags the crash-safety scanner relies on).
//!
//! Operations go through the `nft` command, which is present on every
//! kernel that has nftables enabled. The `nft -j` output drives the
//! snapshot; contract tests cross-check against `nft list ruleset`.

use std::io;
use std::process::Command;
use vfawn_route::PolicyRule;

/// Manages the nftables table that holds rules rtnetlink cannot express.
pub struct NftablesBackend {
    table: String,
    tag: String,
}

impl NftablesBackend {
    /// Create a backend managing the table for one instance.
    ///
    /// The table name and tag both carry the instance identifier, so
    /// `nft list ruleset` output is self-describing and the crash-safety
    /// scanner can find our rules even when the process is gone.
    pub fn new(instance_id: &str) -> Self {
        Self {
            table: format!("vfawn_{instance_id}"),
            tag: format!("vfawn-{instance_id}"),
        }
    }

    /// Ensure the table and its chains exist. Idempotent.
    pub fn ensure_table(&self) -> io::Result<()> {
        // nft add table only creates if absent; errors surface if the
        // kernel rejects (e.g. no nftables module loaded).
        self.nft(&format!("add table inet {}", self.table))?;
        self.nft(&format!(
            "add chain inet {} prerouting {{ type filter hook prerouting priority -150 ; }}",
            self.table
        ))?;
        Ok(())
    }

    /// Remove the entire table and everything in it. Idempotent.
    pub fn drop_table(&self) -> io::Result<()> {
        self.nft(&format!("delete table inet {}", self.table))
    }

    /// Add the DNS leak-prevention rule: traffic to port 53 goes to the
    /// main routing table, so DNS queries bypass the captured path.
    ///
    /// This is the rule rtnetlink cannot express (policy rules have no
    /// dport matching). The comment carries the instance tag.
    pub fn add_dns_leak_rule(&self) -> io::Result<()> {
        self.nft(&format!(
            "add rule inet {} prerouting udp dport 53 accept comment \"{} dns-leak\"",
            self.table, self.tag
        ))
    }

    /// Add the strict-route family block: drop all IPv6 traffic when the
    /// configuration did not enable the v6 family.
    pub fn add_strict_route_block(&self) -> io::Result<()> {
        self.nft(&format!(
            "add rule inet {} prerouting meta nfproto ipv6 drop comment \"{} strict-route\"",
            self.table, self.tag
        ))
    }

    /// Apply one of our policy rules that needs nftables features.
    ///
    /// Returns `true` if the rule was handled here, `false` if the rule
    /// should fall through to the rtnetlink backend.
    pub fn apply_rule(&self, rule: &PolicyRule) -> io::Result<bool> {
        // Rules with a dport selector land here; everything else goes to
        // rtnetlink.
        if let Some(dport) = rule.selector.dport {
            self.nft(&format!(
                "add rule inet {} prerouting udp dport {} accept comment \"{}\"",
                self.table, dport, self.tag
            ))?;
            return Ok(true);
        }
        Ok(false)
    }

    /// List all rules in our table, tagged or not.
    pub fn list_rules(&self) -> io::Result<Vec<String>> {
        let output = Command::new("nft")
            .args(["list", "chain", "inet", &self.table, "prerouting"])
            .output()
            .map_err(|e| io::Error::other(format!("nft list: {e}")))?;
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(text
            .lines()
            .filter(|l| l.trim_start().starts_with(&self.tag) || l.contains(&self.tag))
            .map(|l| l.trim().to_string())
            .collect())
    }

    /// Check whether any rule with our tag exists.
    pub fn has_tagged_rules(&self) -> io::Result<bool> {
        Ok(!self.list_rules()?.is_empty())
    }

    fn nft(&self, cmd: &str) -> io::Result<()> {
        let output = Command::new("nft")
            .arg(cmd)
            .output()
            .map_err(|e| io::Error::other(format!("nft exec: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "No such file or directory" on delete = already gone.
            if cmd.starts_with("delete") && stderr.contains("No such file") {
                return Ok(());
            }
            return Err(io::Error::other(format!("nft: {stderr}")));
        }
        Ok(())
    }
}

/// Convenience: run `nft list ruleset` and return lines mentioning vfawn.
/// Used by the crash-safety scanner (task 018) to find orphan rules.
pub fn find_vfawn_rules() -> Vec<String> {
    let output = Command::new("nft").args(["list", "ruleset"]).output().ok();
    let Some(output) = output else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| l.contains("vfawn"))
        .map(|l| l.trim().to_string())
        .collect()
}
