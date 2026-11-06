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
        let mut state = Self {
            links_up: snapshot
                .adapters
                .iter()
                .filter(|adapter| adapter.up)
                .map(|adapter| adapter.name.clone())
                .collect(),
            default_interface: None,
        };
        // The default route is the 0.0.0.0/0 row with the lowest
        // metric; the platform keeps one table, so the search is a
        // scan. A second table query for one row would be honest too;
        // scanning the route snapshot keeps one API family per poll.
        if let Ok(routes) = default_route_owner(&snapshot) {
            state.default_interface = routes;
        }
        state
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

/// The interface owning the default route, from the route table.
fn default_route_owner(
    snapshot: &crate::windows::route_backend::AdapterSnapshot,
) -> io::Result<Option<String>> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    // SAFETY: the table the kernel filled is freed before return; the
    // rows are read inside the lifetime of that fill.
    #[expect(unsafe_code)]
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(AF_INET, &mut table) != ERROR_SUCCESS || table.is_null() {
            return Ok(None);
        }
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let mut best: Option<(u32, u32)> = None; // (metric, index)
        for row in rows {
            let prefix = &row.DestinationPrefix;
            let is_default = prefix.PrefixLength == 0
                && prefix.Prefix.si_family == AF_INET
                && prefix.Prefix.Ipv4.sin_addr.S_un.S_addr == 0;
            if is_default && best.is_none_or(|(metric, _)| row.Metric < metric) {
                best = Some((row.Metric, row.InterfaceIndex));
            }
        }
        FreeMibTable(table.cast());
        Ok(best.and_then(|(_, index)| {
            snapshot
                .adapters
                .iter()
                .find(|adapter| adapter.index == index)
                .map(|adapter| adapter.name.clone())
        }))
    }
}
