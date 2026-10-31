// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The UDP NAT table: which internal endpoint a return datagram belongs
//! to, and when an idle mapping stops being one.
//!
//! The table sits in core, not in a stack backend, because both the
//! transitional backend and the in-house stack need identical NAT
//! semantics: symmetric mode keys sessions by five-tuple, while
//! endpoint-independent mode keys them by internal endpoint and tracks
//! each contacted remote as a separate idle path inside the session.
//! Return traffic is accepted only from a live path: a third party
//! that never received an outbound datagram gets nothing back, which is
//! what the peer-to-peer use of endpoint-independent mode actually
//! wants.
//!
//! Every method takes the current instant, so tests drive expiry with
//! fictional clocks and the production sweep passes a real one. Each
//! shard keeps two ordered indexes beside its map: one by expiry
//! deadline (what the sweep walks) and one by last activity (what
//! capacity eviction walks, since "least recently used" and "closest to
//! expiring" are different orders once sessions and remote paths share
//! a table with different idle budgets). Entry counts are approximate
//! under concurrency, an eviction decision may race a simultaneous
//! insert, which is fine because capacity is a memory guard, not an
//! accounting rule.

use crate::CloseReason;
use crate::config::{UdpNatConfig, UdpSessionMode};
use crate::session::FlowTrackerHook;
use std::collections::{BTreeMap, HashMap, hash_map::RandomState};
use std::hash::{BuildHasher, Hash};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Capacity when the config asks for the built-in default (zero).
const DEFAULT_MAX_ENTRIES: usize = 16384;

/// How many lock shards the table is cut into. The count is a
/// construction parameter sized for the multi-shard data plane; the
/// default simply keeps concurrent lookups off one another's way.
const DEFAULT_SHARDS: usize = 4;

/// How much idle time a per-remote path inside an endpoint-independent
/// session keeps, relative to the session timeout. Shorter than the
/// session itself: a remote that stopped answering should stop holding
/// return-path state even while the endpoint stays alive.
const REMOTE_IDLE_FRACTION: u32 = 2;

/// The outcome of classifying an outbound datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpFlowOutcome {
    /// Identity of the session the datagram belongs to.
    pub session_id: u64,
    /// A new session was created for this datagram.
    pub created: bool,
    /// Endpoint-independent mode only: a previously unseen remote was
    /// added as a return path to an existing session.
    pub remote_added: bool,
}

/// A UDP NAT table.
pub struct UdpNat {
    mode: UdpSessionMode,
    timeout: Duration,
    max_entries: usize,
    shards: Vec<Mutex<ShardInner>>,
    hasher: RandomState,
    entries: AtomicUsize,
    next_id: AtomicU64,
    tie_break: AtomicU64,
    evicted_sessions: AtomicU64,
}

struct ShardInner {
    sessions: HashMap<SessionKey, Session>,
    /// Ordered by expiry deadline; the sweep walks it from the front.
    expire_at: BTreeMap<(Instant, u64), Item>,
    /// Ordered by last activity; capacity eviction walks it from the
    /// front, which is the least recently used item.
    last_used: BTreeMap<(Instant, u64), Item>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SessionKey {
    source: SocketAddr,
    /// None in endpoint-independent mode: the session spans remotes.
    remote: Option<SocketAddr>,
}

struct Session {
    id: u64,
    tracker: Option<Arc<dyn FlowTrackerHook>>,
    timeout: Duration,
    /// Index keys in both shard indexes, for exact removal.
    expire_index: (Instant, u64),
    use_index: (Instant, u64),
    remotes: HashMap<SocketAddr, RemotePath>,
}

struct RemotePath {
    expire_index: (Instant, u64),
    use_index: (Instant, u64),
}

#[derive(Clone, Copy)]
enum Item {
    Session(SessionKey),
    Remote(SessionKey, SocketAddr),
}

impl UdpNat {
    /// A table with the default shard count.
    pub fn new(mode: UdpSessionMode, timeout: Duration, max_entries: u32) -> Self {
        Self::with_shards(mode, timeout, max_entries, DEFAULT_SHARDS)
    }

    /// A table cut into `shards` independently locked pieces. Session
    /// placement is stable for the life of the table, so every operation
    /// on a flow touches exactly one shard.
    pub fn with_shards(
        mode: UdpSessionMode,
        timeout: Duration,
        max_entries: u32,
        shards: usize,
    ) -> Self {
        Self {
            mode,
            timeout,
            max_entries: if max_entries == 0 {
                DEFAULT_MAX_ENTRIES
            } else {
                max_entries as usize
            },
            shards: (0..shards.max(1))
                .map(|_| {
                    Mutex::new(ShardInner {
                        sessions: HashMap::new(),
                        expire_at: BTreeMap::new(),
                        last_used: BTreeMap::new(),
                    })
                })
                .collect(),
            hasher: RandomState::new(),
            entries: AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            tie_break: AtomicU64::new(0),
            evicted_sessions: AtomicU64::new(0),
        }
    }

    /// Build a table from the config sections: NAT mode and capacity
    /// from `nat`, idle timeout from `udp_timeout`.
    pub fn from_config(nat: &UdpNatConfig, udp_timeout: Duration) -> Self {
        Self::new(nat.mode, udp_timeout, nat.max_entries)
    }

    /// Classify an outbound datagram from `source` toward `remote`.
    ///
    /// The tracker and timeout land on the session; the latest call
    /// wins, so a host re-registering a flow with fresh state replaces
    /// what was stored. Creating entries over capacity evicts the least
    /// recently used item instead of refusing the flow.
    pub fn on_outbound(
        &self,
        source: SocketAddr,
        remote: SocketAddr,
        tracker: Option<Arc<dyn FlowTrackerHook>>,
        timeout_override: Option<Duration>,
        now: Instant,
    ) -> UdpFlowOutcome {
        let key = self.session_key(source, remote);
        let timeout = timeout_override.unwrap_or(self.timeout);
        let outcome = {
            let mut shard = self.lock_shard(&key);

            if let Some(session) = shard.sessions.get_mut(&key) {
                session.tracker = tracker;
                session.timeout = timeout;
                let id = session.id;
                self.refresh_session(&mut shard, &key, now);
                let fresh_remote = !shard.sessions[&key].remotes.contains_key(&remote);
                if fresh_remote {
                    self.add_remote(&mut shard, &key, remote, now);
                    self.entries.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.touch_remote(&mut shard, &key, remote, now);
                }
                UdpFlowOutcome {
                    session_id: id,
                    created: false,
                    remote_added: fresh_remote,
                }
            } else {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                let session = Session {
                    id,
                    tracker,
                    timeout,
                    expire_index: (
                        now + timeout,
                        self.tie_break.fetch_add(1, Ordering::Relaxed),
                    ),
                    use_index: (now, self.tie_break.fetch_add(1, Ordering::Relaxed)),
                    remotes: HashMap::new(),
                };
                shard.sessions.insert(key, session);
                self.index_session(&mut shard, &key);
                self.add_remote(&mut shard, &key, remote, now);
                self.entries.fetch_add(2, Ordering::Relaxed);

                UdpFlowOutcome {
                    session_id: id,
                    created: true,
                    remote_added: false,
                }
            }
        };

        // Trim after the insert, with no shard lock held: the invariant
        // is that the table sits at capacity or below once this call
        // returns, and the eviction pass locks shards of its own.
        if self.entries.load(Ordering::Relaxed) > self.max_entries {
            self.evict_until_roomy();
        }

        outcome
    }

    /// Classify a return datagram from `remote` toward `source`.
    ///
    /// `Some` means the path is live: the datagram belongs to the
    /// returned session and the path's idle state was refreshed.
    /// `None` means drop it: either the endpoint is unknown, or the
    /// remote never had (or no longer has) a live path.
    pub fn on_inbound(&self, source: SocketAddr, remote: SocketAddr, now: Instant) -> Option<u64> {
        let key = self.session_key(source, remote);
        let mut shard = self.lock_shard(&key);
        let session = shard.sessions.get(&key)?;
        if !session.remotes.contains_key(&remote) {
            return None;
        }
        let id = session.id;
        self.refresh_session(&mut shard, &key, now);
        self.touch_remote(&mut shard, &key, remote, now);
        Some(id)
    }

    /// Drop everything past its deadline. Every expired session reports
    /// `closed(Timeout)` to its tracker; expired per-remote paths just
    /// disappear. Returns the number of sessions reaped.
    pub fn sweep(&self, now: Instant) -> usize {
        let mut reaped = 0;
        for slot in &self.shards {
            let mut shard = slot.lock().expect("nat shard lock");
            while let Some((&(deadline, _), _)) = shard.expire_at.iter().next() {
                if deadline > now {
                    break;
                }
                let (_, item) = shard.expire_at.pop_first().expect("front exists");
                if self.remove_item(&mut shard, item) == Removal::Session {
                    reaped += 1;
                }
            }
        }
        reaped
    }

    /// Sessions currently resident.
    pub fn session_count(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().expect("nat shard lock").sessions.len())
            .sum()
    }

    /// Sessions evicted for capacity since construction.
    pub fn evicted_by_capacity(&self) -> u64 {
        self.evicted_sessions.load(Ordering::Relaxed)
    }

    /// Evict least-recently-used items until the table is below
    /// capacity. Victims come from the activity index, and each pass
    /// locks only the shard owning the current front.
    fn evict_until_roomy(&self) {
        while self.entries.load(Ordering::Relaxed) > self.max_entries {
            let fronts = self
                .shards
                .iter()
                .map(|s| {
                    s.lock()
                        .expect("nat shard lock")
                        .last_used
                        .keys()
                        .next()
                        .copied()
                })
                .collect::<Vec<_>>();
            let Some(index) = fronts
                .iter()
                .enumerate()
                .filter_map(|(i, k)| k.map(|k| (k, i)))
                .min()
                .map(|(_, i)| i)
            else {
                break;
            };
            let mut shard = self.shards[index].lock().expect("nat shard lock");
            let Some((_, item)) = shard.last_used.pop_first() else {
                continue;
            };
            if matches!(self.remove_item(&mut shard, item), Removal::Session) {
                self.evicted_sessions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Remove an item from maps and both indexes, whatever it is.
    fn remove_item(&self, shard: &mut ShardInner, item: Item) -> Removal {
        match item {
            Item::Session(key) => self.drop_session(shard, &key),
            Item::Remote(key, remote) => self.drop_remote(shard, &key, remote),
        }
    }

    /// Refresh the session's aggregate indexes after activity.
    fn refresh_session(&self, shard: &mut ShardInner, key: &SessionKey, now: Instant) {
        let Some(session) = shard.sessions.get_mut(key) else {
            return;
        };
        shard.expire_at.remove(&session.expire_index);
        shard.last_used.remove(&session.use_index);
        session.expire_index = (
            now + session.timeout,
            self.tie_break.fetch_add(1, Ordering::Relaxed),
        );
        session.use_index = (now, self.tie_break.fetch_add(1, Ordering::Relaxed));
        self.index_session(shard, key);
    }

    /// Insert the session's current index entries.
    fn index_session(&self, shard: &mut ShardInner, key: &SessionKey) {
        let Some(session) = shard.sessions.get(key) else {
            return;
        };
        shard
            .expire_at
            .insert(session.expire_index, Item::Session(*key));
        shard
            .last_used
            .insert(session.use_index, Item::Session(*key));
    }

    /// Add a fresh return path to a session.
    fn add_remote(
        &self,
        shard: &mut ShardInner,
        key: &SessionKey,
        remote: SocketAddr,
        now: Instant,
    ) {
        let Some(session) = shard.sessions.get_mut(key) else {
            return;
        };
        let expire = (
            self.remote_deadline(now, session.timeout),
            self.tie_break.fetch_add(1, Ordering::Relaxed),
        );
        let used = (now, self.tie_break.fetch_add(1, Ordering::Relaxed));
        shard.expire_at.insert(expire, Item::Remote(*key, remote));
        shard.last_used.insert(used, Item::Remote(*key, remote));
        session.remotes.insert(
            remote,
            RemotePath {
                expire_index: expire,
                use_index: used,
            },
        );
    }

    /// Refresh one remote path after traffic with that remote.
    fn touch_remote(
        &self,
        shard: &mut ShardInner,
        key: &SessionKey,
        remote: SocketAddr,
        now: Instant,
    ) {
        let Some(session) = shard.sessions.get_mut(key) else {
            return;
        };
        let Some(path) = session.remotes.get_mut(&remote) else {
            return;
        };
        shard.expire_at.remove(&path.expire_index);
        shard.last_used.remove(&path.use_index);
        path.expire_index = (
            self.remote_deadline(now, session.timeout),
            self.tie_break.fetch_add(1, Ordering::Relaxed),
        );
        path.use_index = (now, self.tie_break.fetch_add(1, Ordering::Relaxed));
        shard
            .expire_at
            .insert(path.expire_index, Item::Remote(*key, remote));
        shard
            .last_used
            .insert(path.use_index, Item::Remote(*key, remote));
    }

    /// Remove a whole session; every entry it contributed goes with it.
    fn drop_session(&self, shard: &mut ShardInner, key: &SessionKey) -> Removal {
        let Some(mut session) = shard.sessions.remove(key) else {
            return Removal::None;
        };
        shard.expire_at.remove(&session.expire_index);
        shard.last_used.remove(&session.use_index);
        for path in session.remotes.values() {
            shard.expire_at.remove(&path.expire_index);
            shard.last_used.remove(&path.use_index);
        }
        let held = 1 + session.remotes.len();
        self.entries.fetch_sub(held, Ordering::Relaxed);
        let tracker = session.tracker.take();
        session.remotes.clear();
        if let Some(tracker) = tracker {
            tracker.closed(CloseReason::Timeout);
        }
        Removal::Session
    }

    /// Remove one per-remote path, leaving the session itself.
    fn drop_remote(&self, shard: &mut ShardInner, key: &SessionKey, remote: SocketAddr) -> Removal {
        let Some(session) = shard.sessions.get_mut(key) else {
            return Removal::None;
        };
        let Some(path) = session.remotes.remove(&remote) else {
            return Removal::None;
        };
        shard.expire_at.remove(&path.expire_index);
        shard.last_used.remove(&path.use_index);
        self.entries.fetch_sub(1, Ordering::Relaxed);
        Removal::Remote
    }

    fn remote_deadline(&self, now: Instant, timeout: Duration) -> Instant {
        now + timeout / REMOTE_IDLE_FRACTION
    }

    fn session_key(&self, source: SocketAddr, remote: SocketAddr) -> SessionKey {
        SessionKey {
            source,
            remote: match self.mode {
                UdpSessionMode::Symmetric => Some(remote),
                UdpSessionMode::EndpointIndependent => None,
            },
        }
    }

    fn lock_shard(&self, key: &SessionKey) -> std::sync::MutexGuard<'_, ShardInner> {
        let index = (self.hasher.hash_one(key) as usize) % self.shards.len();
        self.shards[index].lock().expect("nat shard lock")
    }
}

#[derive(PartialEq, Eq)]
enum Removal {
    Session,
    Remote,
    None,
}
