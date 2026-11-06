// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Network event monitoring on darwin: the poll-diff shape over the
//! system's own reporter. A thread asks the route table for the
//! default route's interface, compares with the previous answer, and
//! pushes the difference as events — the same contract the Linux
//! monitor holds, where the PF_ROUTE socket would be the
//! subscription optimization this poll shape leaves room for.

use std::io;
use std::process::Command;
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
                        match tx.try_send(event) {
                            Ok(()) => {}
                            // The host is not draining fast enough;
                            // the contract says events are lossy.
                            Err(TrySendError::Full(_)) => {}
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

/// The state a poll reads: which interface owns the default route.
/// The up-link set stays out until a second reporter earns its keep —
/// the default-route answer alone drives both events the consumers
/// re-query anyway.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MonitorState {
    default_interface: Option<String>,
}

impl MonitorState {
    fn capture() -> Self {
        Self {
            default_interface: default_interface(),
        }
    }

    fn diff(&self, new: &Self) -> Vec<MonitorEvent> {
        let mut events = Vec::new();
        if self.default_interface != new.default_interface {
            events.push(MonitorEvent::NetworkChanged);
            events.push(MonitorEvent::DefaultInterfaceChanged {
                name: new.default_interface.clone(),
            });
        }
        events
    }
}

/// The interface the default route leaves through, as the system's
/// own reporter names it. A missing default route reads as `None`,
/// which is itself a reportable answer.
fn default_interface() -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some("interface:"), Some(name)) => Some(name.to_string()),
            _ => None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The system's own reporter names a default route on any machine
    /// with a network; a capture that answers nothing says the parse
    /// broke, not that the network vanished.
    #[test]
    fn the_default_route_has_a_name() {
        let name = default_interface();
        assert!(
            name.is_some_and(|n| !n.is_empty()),
            "route -n get default should name the default interface"
        );
    }
}
