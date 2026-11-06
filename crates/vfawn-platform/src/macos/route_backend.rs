// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The Darwin route backend: routes through the system's `route`
//! command, snapshots through `netstat -rn`. Darwin has no policy
//! rules — the Linux rule concept maps to interface-scoped routes and
//! route metrics, which the desired state's adapter layer expresses
//! before it reaches here. The command shape is what the system's own
//! tools use (and what sing-tun's darwin path exercises in the same
//! seat); a PF_ROUTE socket replaces it when the syscall count
//! matters, which the reconciliation cadence has not yet asked.

use std::io;
use std::process::Command;

use ipnet::IpNet;
use vfawn_route::backend::RouteBackend;
use vfawn_route::model::{ObservedState, RouteEntry, RouteOp};

/// The Darwin route backend: one command per operation, idempotent by
/// the kernel's own tolerance (adding an existing route is EEXIST,
/// which this backend treats as success).
#[derive(Default)]
pub struct DarwinRouteBackend;

impl DarwinRouteBackend {
    pub fn new() -> Self {
        Self
    }

    /// Run `route` with the given arguments, treating EEXIST and
    /// ESRCH (already there / already gone) as success — the
    /// reconciler's idempotence requirement.
    fn route(&self, args: &[&str]) -> io::Result<()> {
        let output = Command::new("route")
            .args(args)
            .output()
            .map_err(|e| io::Error::other(format!("route command: {e}")))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The kernel's own idempotence: adding a route that exists
        // and deleting one that doesn't are both no-ops here.
        if stderr.contains("File exists") || stderr.contains("not in table") {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "route {} failed: {stderr}",
            args.join(" ")
        )))
    }

    /// One route's `route add` arguments: the destination, the
    /// gateway or interface, and the optional metric as the cloning
    /// flag carries priority.
    fn add_route_args(entry: &RouteEntry) -> Vec<String> {
        let mut args = vec!["add".to_string()];
        match &entry.gateway {
            Some(gateway) => {
                args.push(format!("{}", entry.destination));
                args.push(format!("{gateway}"));
            }
            None => {
                // Interface-scoped route: the destination is
                // reachable through the named interface directly.
                args.push(format!("{}", entry.destination));
                if let Some(interface) = &entry.interface {
                    args.push("-interface".to_string());
                    args.push(interface.clone());
                }
            }
        }
        if entry.metric > 0 {
            args.push(format!("-hopcount {}", entry.metric));
        }
        args
    }

    fn remove_route_args(entry: &RouteEntry) -> Vec<String> {
        vec!["delete".to_string(), format!("{}", entry.destination)]
    }
}

impl RouteBackend for DarwinRouteBackend {
    fn snapshot(&self) -> io::Result<ObservedState> {
        // The routing table through the system's own reporter. The
        // output is stable across macOS versions (the format has not
        // changed since the BSD lineage).
        let output = Command::new("netstat")
            .args(["-rn", "-f", "inet"])
            .output()
            .map_err(|e| io::Error::other(format!("netstat: {e}")))?;
        if !output.status.success() {
            return Err(io::Error::other("netstat failed"));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut routes = Vec::new();
        for line in text.lines().skip_while(|l| !l.contains("Destination")) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[0] == "Destination" {
                continue;
            }
            let destination = fields[0];
            let gateway = fields[1];
            let interface = fields[3];
            let dest = match destination.parse::<IpNet>() {
                Ok(net) => net,
                Err(_) => continue, // a host route or a non-inet line
            };
            let gw = gateway.parse::<std::net::IpAddr>().ok();
            routes.push(RouteEntry {
                table: 0, // darwin has one table
                destination: dest,
                gateway: gw,
                interface: Some(interface.to_string()),
                metric: 0,
            });
        }
        Ok(ObservedState {
            addresses: Vec::new(),
            routes,
            rules: Vec::new(),
        })
    }

    fn apply(&self, op: &RouteOp) -> io::Result<()> {
        match op {
            RouteOp::AddRoute(entry) => {
                let args = Self::add_route_args(entry);
                let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                self.route(&refs)
            }
            RouteOp::RemoveRoute(entry) => {
                let args = Self::remove_route_args(entry);
                let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                self.route(&refs)
            }
            // Addresses ride the device layer on darwin (the utun
            // creation already sets them); the route engine's model
            // sees them as facts, not operations.
            RouteOp::AddAddress(_) | RouteOp::RemoveAddress(_) => Ok(()),
            // Darwin has no policy rules; the desired state's adapter
            // expresses rule-shaped intent as interface-scoped routes.
            RouteOp::AddRule(_) | RouteOp::RemoveRule(_) => Ok(()),
        }
    }

    fn is_in_effect(&self, op: &RouteOp) -> io::Result<bool> {
        let state = self.snapshot()?;
        match op {
            RouteOp::AddRoute(entry) => Ok(state
                .routes
                .iter()
                .any(|r| r.destination == entry.destination && r.interface == entry.interface)),
            RouteOp::RemoveRoute(entry) => Ok(!state
                .routes
                .iter()
                .any(|r| r.destination == entry.destination)),
            RouteOp::AddAddress(_) | RouteOp::RemoveAddress(_) => Ok(true),
            RouteOp::AddRule(_) | RouteOp::RemoveRule(_) => Ok(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scoped_route_builds_add_arguments() {
        let entry = RouteEntry {
            table: 0,
            destination: "198.18.0.0/15".parse().unwrap(),
            gateway: None,
            interface: Some("utun0".to_string()),
            metric: 0,
        };
        let args = DarwinRouteBackend::add_route_args(&entry);
        assert_eq!(args[0], "add");
        assert_eq!(args[1], "198.18.0.0/15");
        assert_eq!(args[2], "-interface");
        assert_eq!(args[3], "utun0");
    }

    #[test]
    fn a_gw_route_builds_add_arguments() {
        let entry = RouteEntry {
            table: 0,
            destination: "0.0.0.0/0".parse().unwrap(),
            gateway: Some("10.0.0.1".parse().unwrap()),
            interface: None,
            metric: 5,
        };
        let args = DarwinRouteBackend::add_route_args(&entry);
        assert!(args.contains(&"10.0.0.1".to_string()));
        assert!(args.contains(&"-hopcount 5".to_string()));
    }
}
