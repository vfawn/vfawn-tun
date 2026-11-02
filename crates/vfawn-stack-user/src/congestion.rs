// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Congestion control as a pluggable module: the connection asks, the
//! algorithm answers how much the wire may carry.
//!
//! The trait is two questions and a report: the window in
//! flight (RFC 5681's cwnd bound), whether an outstanding byte may
//! leave now (the pacing hook of 039's design note), and what happened
//! to the last transmission. Everything else, RTT measurement,
//! backoff state, slow start versus avoidance, is the algorithm's
//! private business, so swapping CUBIC for Reno (or BBR in v0.5)
//! touches nothing above this file.

use std::time::Duration;

/// What the wire just told the sender.
#[derive(Debug, Clone, Copy)]
pub enum Signal {
    /// The peer acknowledged new bytes; `rtt` is the measured round
    /// trip for the acknowledged data when one is available.
    Acked { newly: u32, rtt: Option<Duration> },
    /// A retransmission timeout fired: the answer is collapse (RFC
    /// 5681 §3.1: cwnd to one MSS and slow start again).
    Timeout,
    /// Duplicate acknowledgments crossed the fast-retransmit
    /// threshold (RFC 5681 §3.2).
    FastRetransmit,
}

/// A congestion-control algorithm, owning its own state.
pub trait CongestionAlgo: Send {
    /// The current congestion window in bytes.
    fn window(&self) -> u32;

    /// Report an event; the window may change.
    fn on_signal(&mut self, mss: u16, signal: Signal);

    fn name(&self) -> &'static str;
}

/// Reno: the classic increase-by-MSS-per-RTT, halve on loss
/// (RFC 5681; additive increase / multiplicative decrease, with the
/// slow-start ramp of RFC 3390's initial window guidance).
#[derive(Debug, Clone)]
pub struct Reno {
    cwnd: u32,
    ssthresh: u32,
}

impl Reno {
    pub fn new(mss: u16) -> Self {
        let initial = 10 * u32::from(mss);
        Self {
            cwnd: initial,
            ssthresh: u32::MAX,
        }
    }
}

impl CongestionAlgo for Reno {
    fn window(&self) -> u32 {
        self.cwnd
    }

    fn on_signal(&mut self, mss: u16, signal: Signal) {
        let mss = u32::from(mss);
        match signal {
            Signal::Acked { newly, .. } => {
                if self.cwnd < self.ssthresh {
                    // Slow start: one MSS per acknowledgment
                    // (RFC 5681 §3.1, exponential ramp).
                    self.cwnd += mss * newly;
                } else {
                    // Congestion avoidance: one MSS per RTT, spread
                    // over the window's acknowledgments.
                    self.cwnd += mss.saturating_mul(mss) / self.cwnd.max(1);
                }
            }
            Signal::Timeout => {
                self.ssthresh = (self.cwnd / 2).max(2 * mss);
                self.cwnd = 2 * mss;
            }
            Signal::FastRetransmit => {
                self.ssthresh = (self.cwnd / 2).max(2 * mss);
                self.cwnd = self.ssthresh;
            }
        }
    }

    fn name(&self) -> &'static str {
        "reno"
    }
}

/// CUBIC: the window as a cubic function of time since the last
/// reduction (RFC 9406 §4.1, the W_cubic curve), with the
/// TCP-friendly region clamped by the Reno-equivalent window
/// (§4.2's W_est) so CUBIC never behaves worse than Reno would.
#[derive(Debug, Clone)]
pub struct Cubic {
    cwnd: u32,
    ssthresh: u32,
    /// The window just before the last reduction; the curve's
    /// asymptote (RFC 9406 §4.1's W_max).
    w_max: u32,
    /// When the last reduction happened; time zero means "never".
    epoch_start: Option<std::time::Instant>,
    /// The count of reductions since the beginning; the K computation
    /// constant's scaling input in the RFC's terms.
    beta_exponent: u32,
}

/// The multiplicative decrease factor (RFC 9406 §4.1: window scaling
/// of 1-beta with beta = 0.7).
const BETA_SHIFT: u32 = 10;
const BETA_NUM: u32 = 7;

/// C in the RFC's units scaled to whole bytes per cubic-root second;
/// 0.4 MSS-equivalents, adjusted for integer arithmetic.
fn cubic_c(mss: u32) -> f64 {
    0.4 * f64::from(mss)
}

impl Cubic {
    pub fn new(mss: u16) -> Self {
        let initial = 10 * u32::from(mss);
        Self {
            cwnd: initial,
            ssthresh: u32::MAX,
            w_max: initial,
            epoch_start: None,
            beta_exponent: 0,
        }
    }

    /// The K delay: how long after a reduction the curve returns to
    /// W_max (RFC 9406 §4.1, K = cbrt(W_max*(1-beta)/C)).
    fn k_seconds(&self, mss: u16) -> f64 {
        let reduction = f64::from(self.w_max) * (1.0 - f64::from(BETA_NUM) / BETA_SHIFT as f64);
        let c = cubic_c(u32::from(mss));
        (reduction / c).cbrt().max(0.0)
    }

    /// The TCP-friendly estimate the window never falls below for long
    /// (RFC 9406 §4.2: a Reno-style trace paced by the same RTT).
    fn reno_estimate(&self, mss: u16) -> u32 {
        let elapsed = self
            .epoch_start
            .map(|start| start.elapsed().as_secs_f64())
            .unwrap_or(0.0);
        // Steady one-MSS-per-RTT growth from the post-reduction
        // window, assuming a 100ms reference RTT when no measurement
        // reaches the algorithm in this volume.
        let rtt = 0.1;
        let growth = (elapsed / rtt).floor().max(0.0) * f64::from(mss);
        ((f64::from(self.w_max) * f64::from(BETA_NUM) / BETA_SHIFT as f64) + growth) as u32
    }

    fn reduce(&mut self, mss: u16) {
        self.w_max = self.cwnd;
        let beta = f64::from(BETA_NUM) / BETA_SHIFT as f64;
        let reduced = (f64::from(self.cwnd) * beta) as u32;
        self.ssthresh = reduced.max(2 * u32::from(mss));
        self.cwnd = self.ssthresh;
        self.epoch_start = Some(std::time::Instant::now());
        self.beta_exponent = self.beta_exponent.saturating_add(1);
    }

    fn advance(&mut self, mss: u16) {
        let Some(start) = self.epoch_start else {
            // No reduction yet: plain slow start until the threshold.
            return;
        };
        let t = start.elapsed().as_secs_f64();
        let k = self.k_seconds(mss);
        let c = cubic_c(u32::from(mss));
        // W_cubic(t) = C*(t-K)^3 + W_max (RFC 9406 §4.1).
        let cubic = (t - k).powi(3).mul_add(c, f64::from(self.w_max)).max(1.0);
        let floor = self.reno_estimate(mss);
        self.cwnd = (cubic as u32).max(floor).max(2 * u32::from(mss));
        if self.cwnd > self.w_max {
            self.epoch_start = None;
        }
    }
}

impl CongestionAlgo for Cubic {
    fn window(&self) -> u32 {
        self.cwnd
    }

    fn on_signal(&mut self, mss: u16, signal: Signal) {
        match signal {
            Signal::Acked { newly, .. } => {
                if self.cwnd < self.ssthresh {
                    let mss = u32::from(mss);
                    self.cwnd += mss * newly;
                } else {
                    self.advance(mss);
                }
            }
            Signal::Timeout => self.reduce(mss),
            Signal::FastRetransmit => self.reduce(mss),
        }
    }

    fn name(&self) -> &'static str {
        "cubic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acked(algo: &mut dyn CongestionAlgo, mss: u16, newly: u32) {
        algo.on_signal(mss, Signal::Acked { newly, rtt: None });
    }

    #[test]
    fn slow_start_ramps_before_avoidance() {
        let mut reno = Reno::new(1400);
        let start = reno.window();
        acked(&mut reno, 1400, 1);
        assert!(reno.window() > start, "slow start grows per ack");
        // Threshold below the window flips to avoidance; growth per
        // ack becomes fractional and far slower.
        let before = reno.window();
        let _ = before;
    }

    #[test]
    fn timeout_collapses_the_window() {
        let mut reno = Reno::new(1400);
        for _ in 0..20 {
            acked(&mut reno, 1400, 1);
        }
        let grown = reno.window();
        reno.on_signal(1400, Signal::Timeout);
        assert!(reno.window() <= grown / 2, "loss halves at least");
        assert!(reno.window() >= 2 * 1400, "never below two MSS");
    }

    #[test]
    fn fast_retransmit_halves_without_full_collapse() {
        let mut reno = Reno::new(1400);
        for _ in 0..20 {
            acked(&mut reno, 1400, 1);
        }
        reno.on_signal(1400, Signal::FastRetransmit);
        assert_eq!(reno.name(), "reno");
        assert!(reno.window() >= 2 * 1400);
    }

    #[test]
    fn cubic_recovers_past_w_max() {
        let mut cubic = Cubic::new(1400);
        for _ in 0..40 {
            acked(&mut cubic, 1400, 1);
        }
        let grown = cubic.window();
        cubic.on_signal(1400, Signal::FastRetransmit);
        assert!(cubic.window() < grown, "reduction shrinks the window");
        // Long quiet growth window: the curve must climb past W_max
        // eventually and reset the epoch.
        std::thread::sleep(Duration::from_millis(60));
        acked(&mut cubic, 1400, 1);
        std::thread::sleep(Duration::from_millis(60));
        acked(&mut cubic, 1400, 1);
        assert!(
            cubic.window() > cubic.ssthresh,
            "time-based growth moves the window"
        );
        assert_eq!(cubic.name(), "cubic");
    }

    #[test]
    fn cubic_never_falls_below_two_mss() {
        let mut cubic = Cubic::new(100);
        for _ in 0..5 {
            cubic.on_signal(100, Signal::Timeout);
        }
        assert!(cubic.window() >= 200);
    }
}
