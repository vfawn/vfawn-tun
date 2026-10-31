// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Network event monitoring on Linux.
//!
//! A background thread periodically reads kernel state (routes, link
//! status, addresses) and compares with the previous snapshot. Changes
//! become `MonitorEvent` values pushed into a bounded channel. The
//! polling interval is a tradeoff between responsiveness and overhead;
//! true netlink multicast subscription is a drop-in optimization for
//! later (the channel interface stays the same).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;
use vfawn_core::MonitorEvent;

/// How many events can queue before the oldest are dropped.
const CHANNEL_CAPACITY: usize = 256;

/// Default polling interval.
const DEFAULT_INTERVAL: Duration = Duration::from_millis(500);

pub struct NetworkMonitor {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    receiver: Option<Receiver<MonitorEvent>>,
}

impl NetworkMonitor {
    /// Start monitoring with the default polling interval.
    pub fn start() -> io::Result<Self> {
        Self::start_with_interval(DEFAULT_INTERVAL)
    }

    /// Start monitoring with a custom polling interval (for tests).
    pub fn start_with_interval(interval: Duration) -> io::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel::<MonitorEvent>(CHANNEL_CAPACITY);
        let flag = Arc::clone(&shutdown);

        let handle = std::thread::Builder::new()
            .name("vfawn-net-monitor".into())
            .spawn(move || {
                let mut state = MonitorState::default();
                loop {
                    if flag.load(Ordering::Acquire) {
                        break;
                    }
                    let new_state = MonitorState::capture();
                    for event in state.diff(&new_state) {
                        // Non-blocking send: drop the event if the channel
                        // is full rather than stalling the monitor thread.
                        match tx.try_send(event) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                // Channel full; the host is not draining
                                // fast enough. Drop the event and move on
                                // (the contract says events are lossy).
                            }
                            Err(TrySendError::Disconnected(_)) => return,
                        }
                    }
                    state = new_state;
                    std::thread::sleep(interval);
                }
            })?;

        Ok(Self {
            shutdown,
            handle: Some(handle),
            receiver: Some(rx),
        })
    }

    /// Take the event receiver; call once.
    pub fn events(&mut self) -> Option<Receiver<MonitorEvent>> {
        self.receiver.take()
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        self.stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// A snapshot of the kernel state relevant to monitoring.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MonitorState {
    /// Interface names that are up (operstate "up").
    links_up: Vec<String>,
    /// The interface that owns the default IPv4 route.
    default_interface: Option<String>,
}

impl MonitorState {
    fn capture() -> Self {
        Self {
            links_up: list_up_interfaces(),
            default_interface: read_default_interface(),
        }
    }

    /// Compare with the previous state; produce events for each change.
    fn diff(&self, new: &Self) -> Vec<MonitorEvent> {
        let mut events = Vec::new();

        // Link state changes: any addition or removal.
        if self.links_up != new.links_up {
            events.push(MonitorEvent::NetworkChanged);
        }

        // Default interface change.
        if self.default_interface != new.default_interface {
            events.push(MonitorEvent::DefaultInterfaceChanged {
                name: new.default_interface.clone(),
            });
        }

        events
    }
}

/// List interfaces whose operstate is "up".
fn list_up_interfaces() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let state_path = format!("/sys/class/net/{name}/operstate");
            if let Ok(state) = std::fs::read_to_string(&state_path)
                && state.trim() == "up"
            {
                names.push(name);
            }
        }
    }
    names.sort();
    names
}

/// Read the default IPv4 route's outgoing interface from /proc/net/route.
/// The kernel writes "iface\tdestination\tgateway\t..." lines; the default
/// route has destination 00000000.
pub(crate) fn read_default_interface() -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    default_interface_from(&content)
}

/// The table parser, split out so its column reading is testable against
/// a captured sample instead of whatever machine runs the tests.
fn default_interface_from(content: &str) -> Option<String> {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        // Field 0: interface name, field 1: destination in hex.
        if fields[1] == "00000000" {
            return Some(fields[0].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::default_interface_from;

    #[test]
    fn default_route_names_its_interface() {
        // Captured column order from a real table: iface first,
        // destination second.
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     wlp3s0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n\
                     wlp3s0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\n";
        assert_eq!(default_interface_from(table), Some("wlp3s0".to_string()));
    }

    #[test]
    fn table_without_a_default_yields_none() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     tun0\t010212C6\t00000000\t0001\t0\t0\t0\t00FFFFFF\n";
        assert_eq!(default_interface_from(table), None);
    }
}
