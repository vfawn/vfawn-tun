// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! OpenWrt firewall4 compatibility for the auto-redirect capture, after
//! sing-tun's `redirect_nftables_rules_openwrt.go` (origin/dev 79ed065).
//!
//! fw4 owns the `inet fw4` table and its input and forward chains drop
//! by policy, so traffic arriving from the device or forwarded into it
//! dies there. fw4 includes every `/etc/nftables.d/*.nft` at the head of
//! its table on each load: a file of ours re-declares the two chains
//! with four rules accepting the device's traffic, which fw4 places
//! ahead of its own, and its own declarations keep the dropping policy.
//! The file goes in with the capture and out with it, each time
//! followed by `fw4 reload`. Without fw4 (no `inet fw4` table, or no
//! `fw4` command), nothing is touched.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const INCLUDE_DIR: &str = "/etc/nftables.d";

/// The include file for the capture owned by `table` on `interface`:
/// sing-tun's, rule for rule.
pub fn include_file(table: &str, interface: &str) -> String {
    let rules = format!(
        "\tiifname \"{interface}\" counter accept comment \"!{table}: Accept traffic from tun\"\n\
         \toifname \"{interface}\" counter accept comment \"!{table}: Accept traffic from tun\"\n"
    );
    format!(
        "chain input {{\n\
         \ttype filter hook input priority filter; policy accept;\n\
         {rules}}}\n\
         chain forward {{\n\
         \ttype filter hook forward priority filter; policy accept;\n\
         {rules}}}\n"
    )
}

/// Where the include file for `table` lives.
pub fn include_path(table: &str) -> PathBuf {
    Path::new(INCLUDE_DIR).join(format!("0-{table}-auto-redirect.nft"))
}

/// Install (or with `cleanup`, remove) the include file and reload fw4:
/// sing-tun's `configureOpenWRTFirewall4`. A host without fw4 is left
/// alone.
pub fn configure(table: &str, interface: &str, cleanup: bool) -> io::Result<()> {
    let Some(fw4) = fw4_command() else {
        return Ok(());
    };
    let path = include_path(table);
    if !cleanup {
        std::fs::write(&path, include_file(table, interface))
            .map_err(|e| io::Error::new(e.kind(), format!("write fw4 rules: {e}")))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    } else if !path.exists() {
        return Ok(());
    } else {
        std::fs::remove_file(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("clean fw4 rules: {e}")))?;
    }
    let output = Command::new(fw4)
        .arg("reload")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| io::Error::other(format!("reload fw4 rules: {e}")))?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "reload fw4 rules: {}{}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// The `fw4` command, when this is a host fw4 manages: its table is
/// loaded and the command is on the path.
fn fw4_command() -> Option<PathBuf> {
    let loaded = Command::new("nft")
        .args(["list", "table", "inet", "fw4"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !loaded {
        return None;
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("fw4"))
            .find(|candidate| candidate.is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_include_file_is_sing_tuns() {
        assert_eq!(
            include_file("vfawn_redirect_vfawn56", "vfawn56"),
            "chain input {\n\
             \ttype filter hook input priority filter; policy accept;\n\
             \tiifname \"vfawn56\" counter accept comment \"!vfawn_redirect_vfawn56: Accept traffic from tun\"\n\
             \toifname \"vfawn56\" counter accept comment \"!vfawn_redirect_vfawn56: Accept traffic from tun\"\n\
             }\n\
             chain forward {\n\
             \ttype filter hook forward priority filter; policy accept;\n\
             \tiifname \"vfawn56\" counter accept comment \"!vfawn_redirect_vfawn56: Accept traffic from tun\"\n\
             \toifname \"vfawn56\" counter accept comment \"!vfawn_redirect_vfawn56: Accept traffic from tun\"\n\
             }\n"
        );
        assert_eq!(
            include_path("vfawn_redirect_vfawn56"),
            Path::new("/etc/nftables.d/0-vfawn_redirect_vfawn56-auto-redirect.nft")
        );
    }
}
