// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! One-key cleanup: remove every trace a vfawn instance left behind.
//! The nftables tables carry their own tag; the policy rules carry
//! their instance's interface in theirs, and a rule survives its
//! instance — the link's death reaps the table's routes but nothing
//! reaps the rule selecting that now-empty table.

use std::io;

/// Remove all nftables tables tagged `vfawn_*` and every policy rule
/// whose instance is gone. On Linux only; other platforms are a no-op
/// with an empty report.
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
        // The rule sweep works through the same backend the reconciler
        // uses, so what it removes is exactly what an install would
        // sweep on startup — this command is that sweep, on demand.
        let backend = std::sync::Arc::new(vfawn_platform::linux::NetlinkBackend::new()?);
        let reconciler = vfawn_route::Reconciler::new(backend);
        let swept = reconciler.sweep_orphans().unwrap_or_default();
        if swept.is_empty() {
            println!("no orphan rules");
        } else {
            println!("swept {} orphan rule(s):", swept.len());
            for rule in swept {
                println!("  {rule}");
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
