// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Developer CLI entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("up") => up_command(&args[2..]),
        Some("bench") => {
            vfawn_bin::bench::run();
            ExitCode::SUCCESS
        }
        Some("cleanup") => {
            let _ = vfawn_bin::cleanup::run_cleanup(true);
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: vfawn-bin <up|bench|cleanup> [options]");
            eprintln!("  up <address/len> [mtu] [--bind-default-iface]");
            eprintln!("                           create a TUN and echo sessions");
            eprintln!("  bench                    packet-processing throughput");
            eprintln!("  cleanup                  remove stale route rules (placeholder)");
            ExitCode::from(2)
        }
    }
}

fn up_command(args: &[String]) -> ExitCode {
    let bind_default_iface = args.iter().any(|a| a == "--bind-default-iface");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let address: String = positional
        .first()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "198.18.0.1/15".to_string());
    let mtu: u32 = positional
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1500);

    // Run `up` on a dedicated thread; the main thread handles signals and
    // unparks it when it is time to stop. The address is owned because
    // the spawned closure must outlive the caller's frame.
    let worker = std::thread::Builder::new()
        .name("vfawn-up".into())
        .spawn(
            move || match vfawn_bin::up::run(&address, mtu, bind_default_iface) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("up: {e}");
                    ExitCode::FAILURE
                }
            },
        )
        .expect("spawn worker thread");

    // Wait for Ctrl-C, then wake the worker so it runs its shutdown chain.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("signal runtime");
    rt.block_on(async {
        let _ = tokio::signal::ctrl_c().await;
    });

    // The worker thread is parked in thread::park(); wake it. A second
    // signal still kills the process (the default handler), which the
    // device-layer cleanup contract tolerates.
    worker.thread().unpark();

    match worker.join() {
        Ok(code) => code,
        Err(_) => ExitCode::FAILURE,
    }
}
