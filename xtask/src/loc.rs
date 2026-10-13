// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Product line-count reporting.
//!
//! Code size is a tracked goal, not an aesthetic preference, so the count
//! needs one deterministic definition applied the same way every time:
//!
//! * scope: `crates/*/src`, the shipped library code;
//! * excluded: `vfawn-testsuite` (test utilities never reach the product
//!   dependency tree), integration test directories, examples and benches;
//! * counted: physical lines minus blanks and comments (doc comments count
//!   as comments; they document, they do not execute).
//!
//! Lines are classified with a plain scan. A string literal whose line
//! happens to start with `//` or `/*` would be miscounted as a comment; that
//! pattern does not occur in this codebase, and switching to a tokenizer
//! later would not change the report format.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Ceilings for the size budget, in counted lines. The intermediate ceiling
/// covers the state before the kernel-NAT and mobile work lands; the final
/// one is the number the project is held to at release.
const BUDGET_PHASE_ONE: u64 = 18_000;
const BUDGET_FINAL: u64 = 45_000;

/// Test scaffolding stays out of the product budget.
const NON_PRODUCT_CRATES: &[&str] = &["vfawn-testsuite"];

#[derive(Default, serde::Serialize)]
struct Report {
    generated_unix: u64,
    total: u64,
    per_crate: BTreeMap<String, u64>,
    budget: Budget,
}

#[derive(Default, serde::Serialize)]
struct Budget {
    phase_one: u64,
    #[serde(rename = "final")]
    final_budget: u64,
    within_phase_one: bool,
}

pub fn run() {
    let root = workspace_root();
    let mut report = Report {
        generated_unix: unix_now(),
        ..Report::default()
    };

    let crates_dir = root.join("crates");
    let mut names = fs::read_dir(&crates_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", crates_dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();

    for name in &names {
        if NON_PRODUCT_CRATES.contains(&name.as_str()) {
            continue;
        }
        let src = crates_dir.join(name).join("src");
        let counted = count_dir(&src);
        report.per_crate.insert(name.clone(), counted);
        report.total += counted;
    }

    report.budget = Budget {
        phase_one: BUDGET_PHASE_ONE,
        final_budget: BUDGET_FINAL,
        within_phase_one: report.total <= BUDGET_PHASE_ONE,
    };

    print_table(&report);
    let out = root.join("bench/results/loc.json");
    fs::create_dir_all(out.parent().unwrap()).expect("create bench/results");
    fs::write(&out, serde_json::to_vec_pretty(&report).unwrap()).expect("write loc.json");
    println!("\nreport written to {}", out.display());
}

fn print_table(report: &Report) {
    let mut out = String::new();
    writeln!(out, "{:<24} {:>8}", "crate", "lines").unwrap();
    writeln!(out, "{}", "-".repeat(34)).unwrap();
    for (name, lines) in &report.per_crate {
        writeln!(out, "{:<24} {:>8}", name, lines).unwrap();
    }
    writeln!(out, "{}", "-".repeat(34)).unwrap();
    writeln!(out, "{:<24} {:>8}", "total", report.total).unwrap();
    print!("{out}");
}

fn count_dir(dir: &Path) -> u64 {
    if !dir.exists() {
        return 0;
    }
    let mut stack = vec![dir.to_path_buf()];
    let mut total = 0;
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                // Integration tests, examples and benches are not product
                // code even when they live inside a product crate.
                if matches!(name.as_str(), "tests" | "examples" | "benches") {
                    continue;
                }
                stack.push(path);
            } else if name.ends_with(".rs") {
                total += count_file(&path);
            }
        }
    }
    total
}

fn count_file(path: &Path) -> u64 {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return 0,
    };
    let mut code = 0;
    let mut in_block_comment = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }
        code += 1;
    }
    code
}

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
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
