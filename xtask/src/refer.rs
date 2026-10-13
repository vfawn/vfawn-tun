// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Upstream baseline bookkeeping.
//!
//! Benchmark numbers are only meaningful against the exact upstream state
//! they were measured on, and the reference implementations move fast. Every
//! benchmark round therefore starts by pinning the checked-out commits of the
//! reference repositories next to the data, so a later reader can answer
//! "which sing-tun was this compared against" from the report directory
//! alone.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Repositories the benchmark baselines depend on. The list stays explicit:
/// anything else under refer/ is reading material, not a baseline.
const TRACKED: &[&str] = &["sing-tun", "sing-box"];

#[derive(serde::Serialize)]
struct RepoState {
    url: String,
    head: String,
    head_subject: String,
    commit_date: String,
}

#[derive(serde::Serialize)]
struct Report {
    generated_unix: u64,
    repos: BTreeMap<String, Option<RepoState>>,
}

pub fn run() {
    let root = workspace_root();
    let mut repos = BTreeMap::new();

    for name in TRACKED {
        repos.insert((*name).to_string(), probe(&root.join("refer").join(name)));
    }

    let report = Report {
        generated_unix: unix_now(),
        repos,
    };
    let out = root.join("bench/results/opponent-head.json");
    fs::create_dir_all(out.parent().unwrap()).expect("create bench/results");
    fs::write(&out, serde_json::to_vec_pretty(&report).unwrap()).expect("write report");
    println!("report written to {}", out.display());
}

fn probe(path: &PathBuf) -> Option<RepoState> {
    if !path.join(".git").exists() {
        eprintln!("warning: {} is not a git checkout, skipped", path.display());
        return None;
    }
    let git = |args: &[&str]| -> Option<String> {
        Command::new("git")
            .arg("-C")
            .arg(path)
            .args(args)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    Some(RepoState {
        url: git(&["remote", "get-url", "origin"])?,
        head: git(&["rev-parse", "HEAD"])?,
        head_subject: git(&["log", "-1", "--format=%s"])?,
        commit_date: git(&["log", "-1", "--format=%cI"])?,
    })
}

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    std::path::Path::new(manifest)
        .parent()
        .expect("xtask sits inside the workspace")
        .to_path_buf()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
