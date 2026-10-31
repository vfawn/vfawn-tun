// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Crash-safety scanner: find and remove rules a previous process left
//! behind.
//!
//! The instance tag (`vfawn-<id>`) is the search key. On startup the
//! scanner runs before any new rules are installed, so a crashed
//! predecessor's state is cleaned before the new instance begins. The
//! `cleanup` CLI subcommand exposes the same logic manually.

use std::io;
use std::process::Command;

/// What one cleanup pass found and did.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct CleanupReport {
    /// nftables tables dropped.
    pub nftables_tables: Vec<String>,
    /// Policy rules removed (rtnetlink).
    pub policy_rules: Vec<String>,
    /// Routes removed from dedicated tables (rtnetlink).
    pub routes: Vec<String>,
}

impl CleanupReport {
    pub fn is_empty(&self) -> bool {
        self.nftables_tables.is_empty() && self.policy_rules.is_empty() && self.routes.is_empty()
    }

    pub fn total(&self) -> usize {
        self.nftables_tables.len() + self.policy_rules.len() + self.routes.len()
    }
}

/// Remove every nftables table whose name starts with `vfawn_`. When
/// `instance_id` is `None`, remove all vfawn tables; otherwise only the
/// one matching the instance.
pub fn cleanup_nftables(instance_id: Option<&str>) -> io::Result<CleanupReport> {
    let mut report = CleanupReport::default();

    // List all tables; filter for vfawn prefix.
    let output = Command::new("nft")
        .args(["-j", "list", "tables"])
        .output()
        .map_err(|e| io::Error::other(format!("nft list tables: {e}")))?;

    let text = String::from_utf8_lossy(&output.stdout);
    // The JSON output has a "nftables" array with table objects. A simple
    // line scan is sufficient here; the format is stable.
    for line in text.lines() {
        // Look for "name": "vfawn_..." patterns.
        if let Some(name) = extract_quoted_after(line, "name") {
            if !name.starts_with("vfawn_") {
                continue;
            }
            let should_remove = match instance_id {
                Some(id) => name == format!("vfawn_{id}"),
                None => true,
            };
            if should_remove {
                let cmd = format!("delete table inet {name}");
                let _ = Command::new("nft").arg(&cmd).output();
                report.nftables_tables.push(name);
            }
        }
    }
    Ok(report)
}

/// Find SSH session source addresses by reading /proc/net/tcp and
/// /proc/net/tcp6 for connections to port 22. Returns the remote peer
/// addresses, so the caller can exclude them from the capture.
pub fn ssh_session_sources() -> Vec<std::net::IpAddr> {
    let mut sources = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            // Field 1 is "local_address:port", field 2 is "remote_address:port".
            // Field 3 is state (01 = ESTABLISHED).
            let state = fields[3];
            if state != "01" {
                continue; // not ESTABLISHED
            }
            let local = fields[1];
            let remote = fields[2];
            // Check if the local port is 22 (0x0016 in hex).
            if let Some(port_str) = local.split(':').nth(1)
                && port_str.eq_ignore_ascii_case("0016")
                && let Some(ip) = parse_proc_addr(remote)
            {
                sources.push(ip);
            }
        }
    }
    sources
}

/// Parse a /proc/net address in "HEXIP:HEXPORT" format.
fn parse_proc_addr(addr: &str) -> Option<std::net::IpAddr> {
    let ip_part = addr.split(':').next()?;
    if ip_part.len() == 8 {
        // IPv4: little-endian hex.
        let bytes = hex_decode(ip_part)?;
        Some(std::net::IpAddr::from([
            bytes[3], bytes[2], bytes[1], bytes[0],
        ]))
    } else if ip_part.len() == 32 {
        // IPv6: four little-endian 32-bit words.
        let bytes = hex_decode(ip_part)?;
        let mut v6 = [0u8; 16];
        for (i, chunk) in bytes.chunks(4).enumerate() {
            if chunk.len() == 4 {
                let word = [chunk[3], chunk[2], chunk[1], chunk[0]];
                v6[i * 4..i * 4 + 4].copy_from_slice(&word);
            }
        }
        Some(std::net::IpAddr::from(v6))
    } else {
        None
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Extract a quoted string value after a key like "name" in a JSON-ish line.
fn extract_quoted_after(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\": \"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
