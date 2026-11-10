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
            eprintln!("                           [--stack native] in-house stack");
            eprintln!("                           create a TUN and echo sessions");
            eprintln!("  bench                    packet-processing throughput");
            eprintln!("  cleanup                  remove stale route rules (placeholder)");
            ExitCode::from(2)
        }
    }
}

fn up_command(args: &[String]) -> ExitCode {
    let bind_default_iface = args.iter().any(|a| a == "--bind-default-iface");
    let stack_native = args.windows(2).any(|w| w == ["--stack", "native"]);
    let relay = args.iter().any(|a| a == "--relay");
    let auto_route = args.iter().any(|a| a == "--auto-route");
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
        .spawn(move || {
            match vfawn_bin::up::run(
                &address,
                mtu,
                bind_default_iface,
                relay,
                auto_route,
                stack_native,
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("up: {e}");
                    ExitCode::FAILURE
                }
            }
        })
        .expect("spawn worker thread");

    // Wait for Ctrl-C, or for the worker to leave on its own (a lost
    // device), then wake the worker so it runs its shutdown chain.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("signal runtime");
    rt.block_on(async {
        let finished = async {
            while !worker.is_finished() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            () = finished => {}
        }
    });

    // The worker parks between stop checks; ask, then wake it. A second
    // signal still kills the process (the default handler), which the
    // device-layer cleanup contract tolerates.
    vfawn_bin::up::request_stop();
    worker.thread().unpark();

    match worker.join() {
        Ok(code) => code,
        Err(_) => ExitCode::FAILURE,
    }
}
