// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The accept layer: SYN cookies, backlog bounding, and the SYN-flood
//! posture (RFC 4987 §3.3's countermeasure taxonomy, cookie branch).
//!
//! A cookie encodes the flow's identity and a time step into the
//! sequence number the server offers (the classic SYN-cookie trick:
//! the server holds no per-half-open-connection state, and a client
//! that completes the handshake proves the cookie by echoing it in its
//! ACK). A flood of SYNs from spoofed addresses therefore costs
//! nothing but the packet parse: no ACK ever comes back, and nothing
//! is retained. This is the feature the reference stacks ship without
//! (their go stack has no SYN-cookie path), which makes it a
//! defensible differentiator rather than parity work.
//!
//! When cookies are off, half-open connections queue under a backlog
//! bound; the queue sheds oldest-first, which is the honest behavior
//! of every socket layer under a flood.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// How long one cookie generation stays valid: a client's ACK must
/// land within two generations of its SYN, tolerating one step of
/// clock skew.
const GENERATION: Duration = Duration::from_secs(60);

/// A time-stepped secret source: the cookie changes every generation,
/// so an old capture cannot be replayed after the window passes.
pub trait CookieSecret: Send {
    fn secret_for(&self, generation: u64) -> u32;
}

/// A fixed secret for tests and deterministic replay.
pub struct FixedSecret(pub u32);

impl CookieSecret for FixedSecret {
    fn secret_for(&self, _generation: u64) -> u32 {
        self.0
    }
}

/// The accept layer's policy and state.
pub struct AcceptQueue {
    /// Cookies on/off; off means half-open state queues under the
    /// backlog bound instead.
    cookies: bool,
    backlog: usize,
    /// Half-open connections when cookies are off; oldest sheds first.
    half_open: VecDeque<(SocketAddr, Instant)>,
    secret: Box<dyn CookieSecret>,
    /// The instant the queue's clock counts from; injectable for tests.
    epoch: Instant,
    established: usize,
}

impl AcceptQueue {
    pub fn new(cookies: bool, backlog: usize, secret: Box<dyn CookieSecret>) -> Self {
        Self {
            cookies,
            backlog,
            half_open: VecDeque::new(),
            secret,
            epoch: Instant::now(),
            established: 0,
        }
    }

    pub fn cookies_enabled(&self) -> bool {
        self.cookies
    }

    fn generation_at(&self, now: Instant) -> u64 {
        now.duration_since(self.epoch).as_secs() / GENERATION.as_secs()
    }

    /// The sequence number to offer a SYN: a cookie derived from the
    /// flow identity and the current time step.
    pub fn sequence_for(&self, source: SocketAddr, now: Instant) -> u32 {
        let generation = self.generation_at(now);
        self.sequence_at_generation(source, generation)
    }

    /// Whether a completing ACK's acknowledged sequence proves a fresh
    /// cookie from this or the previous generation (RFC 4987 §3.3:
    /// the window tolerates the step that may have passed since the
    /// SYN; anything older is not ours to honor).
    pub fn cookie_valid(&self, source: SocketAddr, ack: u32, now: Instant) -> bool {
        let current = self.generation_at(now);
        for generation in [current, current.wrapping_sub(1)] {
            let expected = self.sequence_at_generation(source, generation);
            if expected == ack {
                return true;
            }
        }
        false
    }

    fn sequence_at_generation(&self, source: SocketAddr, generation: u64) -> u32 {
        let mut hash = generation ^ u64::from(self.secret.secret_for(generation));
        // Port first, then address: the order is arbitrary but must
        // match validation, and leading with the port separates flows
        // that differ only there before the address runs follow.
        for byte in source.port().to_be_bytes() {
            hash = hash.wrapping_mul(0x100000001b3) ^ u64::from(byte);
        }
        let octets = match source.ip() {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        for byte in octets {
            hash = hash.wrapping_mul(0x100000001b3) ^ u64::from(byte);
        }
        // A distinct top half: flows that differ in any mixed byte
        // land far apart in sequence space.
        hash ^= hash >> 29;
        (hash >> 16) as u32
    }

    /// A SYN arrived. In cookie mode there is nothing to retain; in
    /// backlog mode the half-open queue gains the flow, shedding the
    /// oldest entry when full.
    pub fn on_syn(&mut self, source: SocketAddr, now: Instant) {
        if self.cookies {
            return; // stateless by construction
        }
        self.half_open.push_back((source, now));
        while self.half_open.len() > self.backlog {
            self.half_open.pop_front();
        }
    }

    /// The verdict on a new SYN: the sequence number to answer with,
    /// or none when the backlog is full and the SYN is dropped (every
    /// socket layer's honest behavior under a flood it cannot cookie).
    /// In cookie mode a handout costs nothing, so nothing is refused.
    pub fn admit(&mut self, source: SocketAddr, now: Instant) -> Option<u32> {
        if !self.cookies && self.half_open.len() >= self.backlog {
            return None;
        }
        self.on_syn(source, now);
        Some(self.secure_isn(source, now))
    }

    /// The ISN a new connection starts from, gVisor's
    /// `generateSecureISN` (`connect.go`): a keyed hash of the flow
    /// plus a 64 ns clock. The clock part keeps a reused four-tuple's
    /// ISN climbing, so a SYN that reopens TIME-WAIT starts above the
    /// old incarnation's sequence space (RFC 1122 4.2.2.13 (1)); the
    /// whole 32-bit space takes ~274 s to wrap, beyond one TIME-WAIT.
    fn secure_isn(&self, source: SocketAddr, now: Instant) -> u32 {
        let ticks = (now.duration_since(self.epoch).as_nanos() >> 6) as u32;
        self.sequence_at_generation(source, 0).wrapping_add(ticks)
    }

    /// The handshake completed for a flow. In backlog mode the
    /// half-open entry (if any) retires.
    pub fn on_established(&mut self, source: SocketAddr) {
        self.established += 1;
        if !self.cookies {
            self.half_open.retain(|(addr, _)| *addr != source);
        }
    }

    /// Shed half-open entries older than the generation window: a SYN
    /// whose ACK never came was either abandoned or spoofed.
    pub fn shed_expired(&mut self, now: Instant) -> usize {
        let before = self.half_open.len();
        self.half_open
            .retain(|(_, at)| now.duration_since(*at) <= GENERATION);
        before - self.half_open.len()
    }

    pub fn half_open_len(&self) -> usize {
        self.half_open.len()
    }

    pub fn established_count(&self) -> usize {
        self.established
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn client(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port))
    }

    fn now() -> Instant {
        Instant::now()
    }

    #[test]
    fn cookie_round_trips_within_two_generations() {
        let queue = AcceptQueue::new(true, 128, Box::new(FixedSecret(0xC0FFEE)));
        let peer = client(40000);
        let offered = queue.sequence_for(peer, now());
        assert!(queue.cookie_valid(peer, offered, now()));
    }

    #[test]
    fn old_generation_cookie_still_valid_once() {
        let queue = AcceptQueue::new(true, 128, Box::new(FixedSecret(0xC0FFEE)));
        let peer = client(40001);
        let offered = queue.sequence_for(peer, now());
        // One full generation later: the previous step stays valid.
        let later = now() + GENERATION;
        assert!(queue.cookie_valid(peer, offered, later));
        // Two generations later: the cookie expired.
        let much_later = now() + GENERATION * 2 + GENERATION / 2;
        assert!(!queue.cookie_valid(peer, offered, much_later));
    }

    #[test]
    fn cookie_is_bound_to_the_flow() {
        let queue = AcceptQueue::new(true, 128, Box::new(FixedSecret(0x1)));
        let offered = queue.sequence_for(client(40002), now());
        assert!(
            !queue.cookie_valid(client(40003), offered, now()),
            "another flow's cookie proves nothing"
        );
    }

    #[test]
    fn flood_of_syns_costs_no_state_in_cookie_mode() {
        let mut queue = AcceptQueue::new(true, 128, Box::new(FixedSecret(0x2)));
        for port in 40000u16..50000 {
            queue.on_syn(client(port), now());
        }
        assert_eq!(queue.half_open_len(), 0, "cookie mode retains nothing");
    }

    #[test]
    fn backlog_sheds_oldest_under_flood() {
        let mut queue = AcceptQueue::new(false, 4, Box::new(FixedSecret(0x3)));
        for port in 40000u16..40010 {
            queue.on_syn(client(port), now());
        }
        assert_eq!(queue.half_open_len(), 4, "bounded by backlog");
        // The oldest entries are gone: the newest four remain.
        assert!(queue.half_open.iter().any(|(a, _)| a.port() == 40009));
        assert!(!queue.half_open.iter().any(|(a, _)| a.port() == 40000));
    }

    #[test]
    fn expired_half_opens_are_shed() {
        let mut queue = AcceptQueue::new(false, 16, Box::new(FixedSecret(0x4)));
        queue.on_syn(client(40020), now());
        let shed = queue.shed_expired(now() + GENERATION * 2);
        assert_eq!(shed, 1);
        assert_eq!(queue.half_open_len(), 0);
    }

    #[test]
    fn establishment_retires_the_half_open_entry() {
        let mut queue = AcceptQueue::new(false, 8, Box::new(FixedSecret(0x5)));
        let peer = client(40030);
        queue.on_syn(peer, now());
        assert_eq!(queue.half_open_len(), 1);
        queue.on_established(peer);
        assert_eq!(queue.half_open_len(), 0);
        assert_eq!(queue.established_count(), 1);
    }

    #[test]
    fn a_reused_four_tuple_gets_a_climbing_isn() {
        let mut queue = AcceptQueue::new(true, 8, Box::new(FixedSecret(0x8)));
        let peer = client(40050);
        let start = queue.epoch;
        let first = queue.admit(peer, start).unwrap();
        // One TIME-WAIT later, within a cookie generation or across
        // one: the second incarnation starts ahead of the first.
        for later in [Duration::from_micros(10), GENERATION, GENERATION * 2] {
            let again = queue.admit(peer, start + later).unwrap();
            let ahead = again.wrapping_sub(first);
            assert!(ahead > 0 && ahead < u32::MAX / 2, "{later:?}: {ahead}");
        }
    }

    #[test]
    fn admit_refuses_only_when_the_backlog_is_full() {
        let mut cookies = AcceptQueue::new(true, 2, Box::new(FixedSecret(0x6)));
        for port in 40000u16..40020 {
            assert!(cookies.admit(client(port), now()).is_some());
        }
        assert_eq!(cookies.half_open_len(), 0);

        let mut backlog = AcceptQueue::new(false, 2, Box::new(FixedSecret(0x7)));
        assert!(backlog.admit(client(40040), now()).is_some());
        assert!(backlog.admit(client(40041), now()).is_some());
        assert!(
            backlog.admit(client(40042), now()).is_none(),
            "a full backlog drops the SYN outright"
        );
        // Retirement makes room again.
        backlog.on_established(client(40040));
        assert!(backlog.admit(client(40043), now()).is_some());
    }
}
