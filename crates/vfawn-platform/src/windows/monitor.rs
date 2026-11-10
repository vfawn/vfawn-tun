// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Network event monitoring on Windows: the poll-diff shape over the
//! same IP Helper tables the route backend snapshots. A thread reads
//! the adapters and the route table, compares with the previous
//! snapshot, and pushes the differences as events — the same contract
//! the Linux monitor holds, where NotifyRouteChange2 would be the
//! subscription optimization this poll shape leaves room for.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;
use vfawn_core::MonitorEvent;

use crate::windows::route_backend::adapter_snapshot;

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

/// The state a poll reads: which adapters are up, and which of them
/// owns the default route.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MonitorState {
    links_up: Vec<String>,
    default_interface: Option<String>,
}

impl MonitorState {
    fn capture() -> Self {
        let snapshot = adapter_snapshot().unwrap_or_default();
        Self {
            links_up: snapshot
                .adapters
                .iter()
                .filter(|adapter| adapter.up)
                .map(|adapter| adapter.name.clone())
                .collect(),
            // Chosen the way the outbound bind chooses it (sing-tun's
            // `checkUpdate`): the TUN's own default route is virtual
            // and never names the way out.
            default_interface: crate::windows::default_if::current_default_interface()
                .ok()
                .flatten()
                .map(|interface| interface.name),
        }
    }

    fn diff(&self, new: &Self) -> Vec<MonitorEvent> {
        let mut events = Vec::new();
        if self.links_up != new.links_up {
            events.push(MonitorEvent::NetworkChanged);
        }
        if self.default_interface != new.default_interface {
            events.push(MonitorEvent::DefaultInterfaceChanged {
                name: new.default_interface.clone(),
            });
        }
        events
    }
}
