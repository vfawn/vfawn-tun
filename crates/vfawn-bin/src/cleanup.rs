// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! One-key rule cleanup: remove every trace a vfawn instance left behind.

use std::io;

/// Remove all nftables tables tagged `vfawn_*`. On Linux only; other
/// platforms are a no-op with an empty report.
pub fn run_cleanup(all: bool) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let report =
            vfawn_platform::linux::cleanup_nftables(if all { None } else { Some("current") })?;
        if report.is_empty() {
            println!("nothing to clean");
        } else {
            println!("cleaned {} items:", report.total());
            for t in &report.nftables_tables {
                println!("  table: {t}");
            }
            for r in &report.policy_rules {
                println!("  rule:  {r}");
            }
            for r in &report.routes {
                println!("  route: {r}");
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = all;
        println!("cleanup requires Linux (nftables/netlink)");
        Ok(())
    }
}
