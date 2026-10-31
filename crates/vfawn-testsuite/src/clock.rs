// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Time control for deterministic replay.
//!
//! A stack that takes time as an explicit parameter (the differential
//! oracle's poll loop, the in-house stack's event loop) can be driven by a
//! virtual clock: the replay harness advances time packet by packet, every
//! run sees the same timestamps, and assertions become exact.
//!
//! Stacks that read the wall clock (the transitional ipstack backend)
//! cannot be virtualized; assertions carry a tolerance window instead.
//! Both paths share the tolerance constant so callers do not guess.

use std::time::Duration;

/// How far a wall-clock-driven assertion may drift before failing. Wide
/// enough for CI scheduling jitter, narrow enough to catch real timing
/// bugs.
pub const WALL_CLOCK_TOLERANCE: Duration = Duration::from_millis(500);

/// A clock the replay harness controls.
///
/// `now()` returns the current virtual instant; `advance_to` jumps to a
/// specific timestamp (as recorded in a pcap); `advance_by` steps forward
/// by a relative amount. The clock never moves on its own.
#[derive(Debug, Clone)]
pub struct VirtualClock {
    /// Microseconds since the capture epoch.
    micros: u64,
}

impl VirtualClock {
    pub fn new() -> Self {
        Self { micros: 0 }
    }

    pub fn from_micros(micros: u64) -> Self {
        Self { micros }
    }

    pub fn now_micros(&self) -> u64 {
        self.micros
    }

    pub fn advance_to(&mut self, micros: u64) {
        self.micros = self.micros.max(micros);
    }

    pub fn advance_by(&mut self, delta: Duration) {
        self.micros += delta.as_micros() as u64;
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}
