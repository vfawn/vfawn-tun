// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Differential testing scaffold: one scenario, two stacks, one verdict.
//!
//! The in-house TCP lands in M3 on the strength of its behavior matching
//! a trusted oracle, so the referee must exist before the players. This
//! module defines what a player is ([`StackDriver`]), what the referee
//! compares ([`SegmentRecord`], the wire-visible effect of a step), and
//! how a mismatch is reported (first difference, with context). The
//! oracle implementation lives beside it (`diff_smoltcp`); the in-house
//! stack implements the same trait in 037 and the same scenarios run
//! unchanged.
//!
//! A scenario is a script of steps: inject a packet after some delay, or
//! just let the clock run. Determinism is the whole point: the same
//! script against the same driver must produce byte-identical records,
//! which the sanity suites assert on both sides.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

/// One wire-visible segment, the unit of comparison. Payload bytes are
/// summarized by length: contents are the application's business, the
/// stack's business is delivering exactly that many of them in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentRecord {
    /// Virtual milliseconds since scenario start.
    pub at_ms: u64,
    pub seq: u32,
    pub ack: u32,
    /// TCP control bits, raw (wire order).
    pub flags: u8,
    pub window: u16,
    pub payload_len: usize,
}

/// What one side of the comparison chose to be strict about. A young
/// stack can mask the fields its oracle computes differently (window
/// sizing, for instance) and tighten the mask as it matures; the mask
/// used is printed with every report so an easy pass is never mistaken
/// for a strict one.
#[derive(Debug, Clone, Copy)]
pub struct CompareMask {
    pub seq: bool,
    pub ack: bool,
    pub flags: bool,
    pub window: bool,
    pub payload_len: bool,
}

impl Default for CompareMask {
    fn default() -> Self {
        Self {
            seq: true,
            ack: true,
            flags: true,
            window: true,
            payload_len: true,
        }
    }
}

impl CompareMask {
    /// Everything compared; the goal every implementation marches to.
    pub const STRICT: Self = Self {
        seq: true,
        ack: true,
        flags: true,
        window: true,
        payload_len: true,
    };

    /// Sequence-bearing truth only: what was sent, acknowledged, and
    /// how much of it. Window policies differ longer than anything else.
    pub const LENIENT: Self = Self {
        window: false,
        ..Self::STRICT
    };
}

/// One step of a scenario script.
#[derive(Debug, Clone)]
pub enum Step {
    /// Hand this packet to the stack after the given virtual delay.
    Inject {
        delay_ms: u64,
        /// A complete IP packet (the TUN framing our stacks consume).
        packet: Vec<u8>,
    },
    /// Let virtual time pass with no input.
    Wait { delay_ms: u64 },
}

/// A named scenario: the script plus the two endpoint addresses every
/// packet in it was built around.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: String,
    /// The client (remote, packet sender) side.
    pub client: SocketAddrV4,
    /// The stack under test listens here.
    pub server: SocketAddrV4,
    pub steps: Vec<Step>,
}

impl Scenario {
    pub fn new(name: &str, client: SocketAddrV4, server: SocketAddrV4) -> Self {
        Self {
            name: name.to_string(),
            client,
            server,
            steps: Vec::new(),
        }
    }

    pub fn inject(&mut self, delay_ms: u64, packet: Vec<u8>) -> &mut Self {
        self.steps.push(Step::Inject { delay_ms, packet });
        self
    }

    pub fn wait(&mut self, delay_ms: u64) -> &mut Self {
        self.steps.push(Step::Wait { delay_ms });
        self
    }
}

/// The player contract: run a scenario, produce its wire-visible
/// effects in order. Implementations own their clock; the runner only
/// ever moves it forward through the steps.
pub trait StackDriver {
    /// Prepare a fresh run: the driver is rebuilt per scenario, but a
    /// reset keeps long-lived implementations honest.
    fn reset(&mut self, scenario: &Scenario);

    /// Apply one step and return the records the stack emitted because
    /// of it, in emission order, stamped with the virtual clock.
    fn step(&mut self, step: &Step) -> Vec<SegmentRecord>;

    /// Any records still pending after the last step (late timers, for
    /// instance) come out here.
    fn finish(&mut self) -> Vec<SegmentRecord> {
        let _ = self;
        Vec::new()
    }
}

/// The referee's verdict on one scenario.
#[derive(Debug)]
pub enum DiffOutcome {
    Identical {
        records: usize,
        mask: CompareMask,
    },
    FirstDifference {
        scenario: String,
        index: usize,
        expected: SegmentRecord,
        actual: SegmentRecord,
        context: Vec<(usize, SegmentRecord, SegmentRecord)>,
        mask: CompareMask,
    },
    LengthMismatch {
        scenario: String,
        expected_len: usize,
        actual_len: usize,
        first_divergence: usize,
        context: Vec<(usize, SegmentRecord, SegmentRecord)>,
    },
}

fn field_mismatch(expected: &SegmentRecord, actual: &SegmentRecord, mask: &CompareMask) -> bool {
    (mask.seq && expected.seq != actual.seq)
        || (mask.ack && expected.ack != actual.ack)
        || (mask.flags && expected.flags != actual.flags)
        || (mask.window && expected.window != actual.window)
        || (mask.payload_len && expected.payload_len != actual.payload_len)
}

/// Run one scenario through two drivers and compare their merged output
/// sequences under the given strictness.
pub fn run_differential(
    scenario: &Scenario,
    expected: &mut dyn StackDriver,
    actual: &mut dyn StackDriver,
    mask: CompareMask,
) -> DiffOutcome {
    expected.reset(scenario);
    actual.reset(scenario);

    let mut left = Vec::new();
    let mut right = Vec::new();
    for step in &scenario.steps {
        left.extend(expected.step(step));
        right.extend(actual.step(step));
    }
    left.extend(expected.finish());
    right.extend(actual.finish());

    let common = left.len().min(right.len());
    for index in 0..common {
        if field_mismatch(&left[index], &right[index], &mask) {
            let start = index.saturating_sub(3);
            let end = (index + 4).min(common);
            return DiffOutcome::FirstDifference {
                scenario: scenario.name.clone(),
                index,
                expected: left[index],
                actual: right[index],
                context: (start..end).map(|i| (i, left[i], right[i])).collect(),
                mask,
            };
        }
    }
    if left.len() != right.len() {
        let first_divergence = common;
        let end = (common + 4).min(left.len().max(right.len()));
        let mut context = Vec::new();
        for i in first_divergence..end {
            let l = left.get(i).copied();
            let r = right.get(i).copied();
            if let (Some(l), Some(r)) = (l, r) {
                context.push((i, l, r));
            }
        }
        return DiffOutcome::LengthMismatch {
            scenario: scenario.name.clone(),
            expected_len: left.len(),
            actual_len: right.len(),
            first_divergence,
            context,
        };
    }
    DiffOutcome::Identical {
        records: left.len(),
        mask,
    }
}

impl std::fmt::Display for DiffOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identical { records, mask } => {
                write!(f, "identical: {records} records (mask: {mask:?})")
            }
            Self::FirstDifference {
                scenario,
                index,
                expected,
                actual,
                context,
                mask,
            } => {
                writeln!(f, "DIFF {scenario}[{index}] (mask {mask:?})")?;
                writeln!(f, "  expected {expected:?}")?;
                writeln!(f, "  actual   {actual:?}")?;
                for (i, l, r) in context {
                    writeln!(f, "  [{i:>3}] {l:?}")?;
                    writeln!(f, "        {r:?}")?;
                }
                Ok(())
            }
            Self::LengthMismatch {
                scenario,
                expected_len,
                actual_len,
                first_divergence,
                context,
            } => {
                writeln!(
                    f,
                    "LENGTH {scenario}: expected {expected_len} records, actual {actual_len}"
                )?;
                for (i, l, r) in context {
                    writeln!(f, "  [{i:>3}] {l:?}")?;
                    writeln!(f, "        {r:?}")?;
                }
                writeln!(f, "  first divergence at {first_divergence}")
            }
        }
    }
}

/// Standard addresses the scenario corpus is built around; small
/// variations on these keep the corpus from baking in one magic pair.
pub fn corpus_client(variant: u8) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::new(192, 0, 2, 1 + variant % 8),
        40000 + (variant as u16) * 13,
    )
}

pub fn corpus_server(_variant: u8) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 200), 80)
}

/// Run a batch of scenarios and panic with the first failure's report;
/// the passing count is returned for logging.
pub fn assert_batch(
    scenarios: &[Scenario],
    expected: &mut dyn StackDriver,
    actual: &mut dyn StackDriver,
    mask: CompareMask,
) -> usize {
    let mut passed = 0;
    let mut first_failure: Option<String> = None;
    for scenario in scenarios {
        match run_differential(scenario, expected, actual, mask) {
            DiffOutcome::Identical { .. } => passed += 1,
            other => {
                if first_failure.is_none() {
                    first_failure = Some(format!("{other}"));
                } else {
                    first_failure = Some(format!("{first_failure:?}\n{other}"));
                }
            }
        }
    }
    if let Some(report) = first_failure {
        panic!("{passed}/{} passed\n{report}", scenarios.len());
    }
    passed
}

/// Duration helper for step building.
pub fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}
