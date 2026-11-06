// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The Windows end-to-end path against a live system: the embedded
//! driver loads, the adapter appears with its address, routes go in
//! and out through the platform's own IP Helper tables, a session
//! echoes through the stack, and an orderly shutdown leaves nothing
//! behind. Run elevated (the CI runner is administrator by default):
//!
//! ```text
//! cargo test -p vfawn --test windows_e2e -- --ignored --exact --nocapture
//! ```

#![cfg(target_os = "windows")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use vfawn::echo::EchoHandler;
use vfawn::instance::Instance;
use vfawn_core::config::VfawnConfig;
use vfawn_platform::windows::WindowsRouteBackend;
use vfawn_route::backend::RouteBackend;
use vfawn_route::model::{RouteEntry, RouteOp};

/// The adapter's own address and the prefix it captures.
const ADAPTER_NET: &str = "198.18.0.1/15";

/// The name the device is created under, so route operations can name
/// the interface without asking the instance for it.
const ADAPTER_NAME: &str = "vfawn0";

/// A prefix this test routes through the adapter purely to prove the
/// backend's add and remove against the live tables.
const CRUD_NET: &str = "198.19.0.0/16";

/// The address inside the captured prefix the echo session runs to.
const SESSION_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
const SESSION_PORT: u16 = 9070;

#[test]
#[ignore]
fn adapter_routes_session_and_clean_teardown() {
    let handler = Arc::new(EchoHandler::new());
    let mut config = VfawnConfig::default();
    config.device.name = Some(ADAPTER_NAME.to_string());
    config.device.mtu = 1500;
    config.device.inet4_address = vec![ADAPTER_NET.parse().unwrap()];
    config.route.auto_route = true;
    // Only the test prefix: an empty capture list means the default
    // route, which on a shared runner would swallow the machine's own
    // network mid-test.
    config.route.route_address = vec![ADAPTER_NET.parse().unwrap()];

    // The device, the address, and the capture.
    let mut instance = Instance::new(config, handler.clone()).expect("instance");
    let adapter = ADAPTER_NAME.to_string();
    instance.start(handler).expect("start");

    let backend = WindowsRouteBackend::new();
    let state = backend.snapshot().expect("snapshot");
    assert!(
        state
            .addresses
            .iter()
            .any(|address| address.interface == adapter),
        "the adapter carries its address"
    );

    // Route CRUD against the live tables, on a prefix nothing else
    // uses: add, observe, remove, observe the absence.
    let route = RouteEntry {
        table: 0,
        destination: CRUD_NET.parse::<IpNet>().unwrap(),
        gateway: None,
        interface: Some(adapter.clone()),
        metric: 1,
    };
    backend
        .apply(&RouteOp::AddRoute(route.clone()))
        .expect("add route");
    let present = backend
        .snapshot()
        .expect("snapshot")
        .routes
        .iter()
        .any(|seen| seen.destination == route.destination && seen.interface == route.interface);
    assert!(present, "the route landed in the system table");

    backend
        .apply(&RouteOp::RemoveRoute(route.clone()))
        .expect("remove route");
    let gone = !backend
        .snapshot()
        .expect("snapshot")
        .routes
        .iter()
        .any(|seen| seen.destination == route.destination);
    assert!(gone, "the route left with the remove");

    // A session through the stack: connect inside the captured
    // prefix, write, and read the echo back.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut stream = loop {
        if Instant::now() > deadline {
            panic!("the echo session never connected");
        }
        match TcpStream::connect((SESSION_ADDR, SESSION_PORT)) {
            Ok(stream) => break stream,
            Err(_) => std::thread::sleep(Duration::from_millis(250)),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let probe = b"vfawn-windows-e2e";
    stream.write_all(probe).expect("write");
    let mut echoed = [0u8; 64];
    let n = stream.read(&mut echoed).expect("echo read");
    assert_eq!(&echoed[..n], probe, "the stack echoed the payload");

    // Orderly shutdown removes the capture; the adapter goes with the
    // device that owned it.
    instance.shutdown().expect("shutdown");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = backend.snapshot().expect("snapshot");
        let adapter_gone = !state
            .addresses
            .iter()
            .any(|address| address.interface == adapter);
        if adapter_gone || Instant::now() > deadline {
            assert!(adapter_gone, "the adapter left with its device");
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
