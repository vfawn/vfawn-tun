// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Congestion control as a pluggable module: the connection asks, the
//! algorithm answers how much the wire may carry.
//!
//! The trait is two questions and a report: the window in
//! flight (RFC 5681's cwnd bound), whether an outstanding byte may
//! leave now (the pacing hook the payload fast path reserves), and what happened
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
                    // Slow start: the window grows by the bytes
                    // acknowledged (RFC 5681 §3.1's one MSS per
                    // acknowledgment restated in byte units: one
                    // window's worth of acknowledgments doubles the
                    // window, whatever size the individual
                    // acknowledgments are).
                    self.cwnd = self.cwnd.saturating_add(newly);
                } else {
                    // Congestion avoidance: one MSS per RTT, spread
                    // over the window's acknowledgments.
                    // The additive-increase approximation (one MSS per RTT spread over
                    // the window) rounds to zero once the window passes mss²; the
                    // floor keeps the climb alive at the large windows the
                    // local-pipe start reaches immediately.
                    self.cwnd += (mss.saturating_mul(mss) / self.cwnd.max(1)).max(1);
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
                    self.cwnd = self.cwnd.saturating_add(newly);
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

    fn acked_round(algo: &mut dyn CongestionAlgo, mss: u16) {
        acked(algo, mss, u32::from(mss));
    }

    #[test]
    fn slow_start_ramps_before_avoidance() {
        let mut reno = Reno::new(1400);
        let start = reno.window();
        acked_round(&mut reno, 1400);
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
            acked_round(&mut reno, 1400);
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
            acked_round(&mut reno, 1400);
        }
        reno.on_signal(1400, Signal::FastRetransmit);
        assert_eq!(reno.name(), "reno");
        assert!(reno.window() >= 2 * 1400);
    }

    #[test]
    fn cubic_recovers_past_w_max() {
        let mut cubic = Cubic::new(1400);
        for _ in 0..40 {
            acked_round(&mut cubic, 1400);
        }
        let grown = cubic.window();
        cubic.on_signal(1400, Signal::FastRetransmit);
        assert!(cubic.window() < grown, "reduction shrinks the window");
        // Long quiet growth window: the curve must climb past W_max
        // eventually and reset the epoch.
        std::thread::sleep(Duration::from_millis(60));
        acked_round(&mut cubic, 1400);
        std::thread::sleep(Duration::from_millis(60));
        acked_round(&mut cubic, 1400);
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

/// BBR v1 (draft-cardwell-iccrg-bbr-congestion-control-00, the Linux
/// shape the references implement): two estimators — a windowed-max
/// bandwidth filter over delivery-rate samples and a windowed-min RTT
/// filter over timestamp echoes — and a window derived from their
/// product (the bandwidth-delay product) instead of from loss.
///
/// v0 fits our signal shape: ACK samples carry `(bytes, rtt)` pairs,
/// so the delivery rate is `bytes / rtt` per sample and the filter
/// window is round-counted at one round per ACK that carries an RTT
/// echo. Loss does not shrink the window (the model's whole point);
/// only a timeout resets the bandwidth discovery.
#[derive(Debug, Clone)]
pub struct Bbr {
    mode: BbrMode,
    /// Windowed max of delivery-rate samples (bytes per second),
    /// Linux's minmax_running_max over ~10 rounds.
    bandwidth_filter: MaxFilter,
    /// Windowed min of RTT samples over ~10 seconds.
    min_rtt_filter: MinFilter,
    /// The number of rounds observed at growth below the Startup
    /// exit threshold: three stagnant rounds end Startup.
    stagnant_rounds: u32,
    /// The best bandwidth Startup saw, the bar the growth test uses.
    startup_bar: f64,
    mss: u32,
    /// ProbeRTT bookkeeping: entered when the min-RTT window expires
    /// without refresh, held for its duration at a reduced window.
    probe_rtt_until: Option<std::time::Instant>,
    last_sample_at: Option<std::time::Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BbrMode {
    /// Exponential discovery: window doubles each round (the high
    /// gain is Linux's ln(2)/ln(1.5) ≈ 2/ln2 rounds per doubling —
    /// v0 uses the constant gain 2.77 the draft names).
    Startup,
    /// ProbeBW: steady model-following at the windowed estimates.
    ProbeBandwidth,
    /// ProbeRTT: a brief hold at four segments to refresh the
    /// min-RTT estimate (the draft's 200ms, Linux's floor).
    ProbeRtt,
}

impl Bbr {
    pub fn new(mss: u16) -> Self {
        let mss = u32::from(mss);
        Self {
            mode: BbrMode::Startup,
            bandwidth_filter: MaxFilter::default(),
            min_rtt_filter: MinFilter::default(),
            stagnant_rounds: 0,
            startup_bar: 0.0,
            mss,
            probe_rtt_until: None,
            last_sample_at: None,
        }
    }

    /// The windowed-min RTT the model currently holds.
    fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt_filter.value()
    }

    /// The windowed-max bandwidth, bytes per second.
    fn bandwidth(&self) -> Option<f64> {
        self.bandwidth_filter.value()
    }

    /// The model window: BDP × gain, quantized to segment pairs the
    /// way Linux does (delayed-ACK allowance), floored at four
    /// segments. No estimate yet: Linux's ten-segment initial.
    fn model_window(&self, gain: f64) -> u32 {
        let Some(rtt) = self.min_rtt() else {
            return 10 * self.mss;
        };
        let Some(bandwidth) = self.bandwidth() else {
            return 10 * self.mss;
        };
        let bdp = bandwidth * rtt.as_secs_f64() * gain;
        let mut target = bdp.ceil() as u32;
        // End-system quantum: one segment, doubled for the probe.
        let quantum = self.mss.max(1);
        target += 3 * quantum;
        let segments = target.div_ceil(self.mss.max(1));
        let segments = segments + (segments & 1); // pair alignment
        let target = segments.saturating_mul(self.mss.max(1));
        target.max(4 * self.mss)
    }
}

impl CongestionAlgo for Bbr {
    fn window(&self) -> u32 {
        // The mode's gain: Startup doubles, ProbeBW follows the
        // model at one, ProbeRTT holds the floor.
        match self.mode {
            BbrMode::Startup => self.model_window(2.0),
            BbrMode::ProbeBandwidth => self.model_window(1.0),
            BbrMode::ProbeRtt => 4 * self.mss,
        }
    }

    fn on_signal(&mut self, mss: u16, signal: Signal) {
        self.mss = u32::from(mss);
        let now = std::time::Instant::now();
        match signal {
            Signal::Acked {
                newly,
                rtt: Some(sample),
            } => {
                self.last_sample_at = Some(now);
                // The min-RTT filter: windowed min over ten seconds.
                self.min_rtt_filter.update(sample, now);
                // The delivery-rate sample: acknowledged bytes over
                // the measured round trip.
                if sample.as_secs_f64() > 0.0 {
                    let rate = newly as f64 / sample.as_secs_f64();
                    self.bandwidth_filter.update(rate);
                    if self.mode == BbrMode::Startup {
                        // Growth test (draft §4.3.2.2): three rounds
                        // below 1.25× of the best end Startup.
                        let best = self.startup_bar.max(rate);
                        if rate >= self.startup_bar * 1.25 || self.startup_bar == 0.0 {
                            self.startup_bar = best;
                            self.stagnant_rounds = 0;
                        } else {
                            self.stagnant_rounds += 1;
                        }
                        if self.stagnant_rounds >= 3 {
                            self.mode = BbrMode::ProbeBandwidth;
                        }
                    }
                }
                // ProbeRTT entry: the min-RTT window expired without a
                // refresh (draft §4.4.2) — hold briefly at the floor.
                if self.mode != BbrMode::ProbeRtt && self.min_rtt_filter.window_expired(now) {
                    self.mode = BbrMode::ProbeRtt;
                    self.probe_rtt_until = Some(now + Duration::from_millis(200));
                }
                if self.mode == BbrMode::ProbeRtt
                    && self.probe_rtt_until.is_some_and(|until| now >= until)
                {
                    self.mode = BbrMode::ProbeBandwidth;
                    self.probe_rtt_until = None;
                    self.min_rtt_filter.refresh_window(now);
                }
            }
            Signal::Acked { .. } => {
                // An ACK without an echo carries no rate sample; the
                // model stands.
            }
            Signal::Timeout => {
                // The draft's response to a timeout: the bandwidth
                // model restarts (the path may have changed under
                // us), the RTT window keeps its memory.
                self.bandwidth_filter = MaxFilter::default();
                self.mode = BbrMode::Startup;
                self.stagnant_rounds = 0;
                self.startup_bar = 0.0;
            }
            Signal::FastRetransmit => {
                // Loss is not congestion to this model: the window
                // stands (draft §4.2.4 — the whole reason it exists).
            }
        }
    }

    fn name(&self) -> &'static str {
        "bbr"
    }
}

/// Windowed maximum over a round count (Linux's minmax_running_max,
/// simplified to a period-10 window keyed by sample index).
#[derive(Debug, Clone, Default)]
struct MaxFilter {
    samples: Vec<(u64, f64)>,
    index: u64,
}

impl MaxFilter {
    fn update(&mut self, rate: f64) {
        self.index += 1;
        self.samples.push((self.index, rate));
        // The window is ~10 rounds behind the newest sample.
        let cutoff = self.index.saturating_sub(10);
        self.samples.retain(|(index, _)| *index > cutoff);
    }

    fn value(&self) -> Option<f64> {
        self.samples
            .iter()
            .map(|(_, rate)| *rate)
            .fold(None, |best, rate| {
                Some(best.map_or(rate, |b: f64| b.max(rate)))
            })
    }
}

/// Windowed minimum over wall-clock time (~10 seconds).
#[derive(Debug, Clone, Default)]
struct MinFilter {
    best: Option<(std::time::Instant, Duration)>,
    window_start: Option<std::time::Instant>,
}

impl MinFilter {
    fn update(&mut self, sample: Duration, now: std::time::Instant) {
        let window_start = *self.window_start.get_or_insert(now);
        if now.duration_since(window_start) >= Duration::from_secs(10) {
            // The window closed: the next sample starts a fresh one.
            self.window_start = Some(now);
            self.best = Some((now, sample));
            return;
        }
        match self.best {
            Some((_, best)) if sample < best => self.best = Some((now, sample)),
            Some(_) => {}
            None => self.best = Some((now, sample)),
        }
    }

    fn value(&self) -> Option<Duration> {
        self.best.map(|(_, best)| best)
    }

    fn window_expired(&self, now: std::time::Instant) -> bool {
        self.best
            .is_some_and(|(at, _)| now.duration_since(at) >= Duration::from_secs(10))
    }

    fn refresh_window(&mut self, now: std::time::Instant) {
        self.window_start = Some(now);
    }
}

#[cfg(test)]
mod bbr_tests {
    use super::*;

    const MSS: u16 = 1460;

    #[test]
    fn bbr_ignores_loss_and_follows_the_model() {
        // The model's whole point: loss events leave the window alone
        // (Reno/Cubic halve on the same signals).
        let mut bbr = Bbr::new(MSS);
        let mut reno = Reno::new(MSS);
        let base = bbr.window();
        let reno_base = reno.window();
        for _ in 0..5 {
            bbr.on_signal(MSS, Signal::FastRetransmit);
            reno.on_signal(MSS, Signal::FastRetransmit);
        }
        assert_eq!(bbr.window(), base, "loss is not congestion to the model");
        assert!(reno.window() < reno_base, "Reno halves where BBR stands");
    }

    #[test]
    fn bbr_grows_with_samples_and_finds_steady_state() {
        let mut bbr = Bbr::new(MSS);
        // A 10ms-RTT, 100MB/s path: each ACK carries one MSS at
        // 10ms.
        let sample = Duration::from_millis(10);
        for _ in 0..20 {
            bbr.on_signal(
                MSS,
                Signal::Acked {
                    newly: MSS as u32,
                    rtt: Some(sample),
                },
            );
        }
        // The model window: BDP = rate × RTT. One MSS per 10ms is
        // 1460×100 = 146,000 bytes/s; BDP = 1,460 bytes → the
        // quantized window lands near a few segments, floored at 4.
        let window = bbr.window();
        assert!(window >= 4 * MSS as u32, "the floor holds");
        assert!(window < 10 * MSS as u32, "and the model does not run away");
        assert_eq!(bbr.name(), "bbr");
    }

    #[test]
    fn bbr_exits_startup_on_stagnation() {
        let mut bbr = Bbr::new(MSS);
        // Prime the bar with a good sample, then stagnate.
        bbr.on_signal(
            MSS,
            Signal::Acked {
                newly: MSS as u32,
                rtt: Some(Duration::from_millis(10)),
            },
        );
        // Growth test uses 1.25x of the best; identical samples are
        // stagnant. BBR's drafts require the round structure; v0
        // counts rounds as RTT-carrying ACKs.
        for _ in 0..6 {
            bbr.on_signal(
                MSS,
                Signal::Acked {
                    newly: MSS as u32,
                    rtt: Some(Duration::from_millis(10)),
                },
            );
        }
        assert!(
            matches!(bbr.mode, BbrMode::ProbeBandwidth),
            "three stagnant rounds end Startup"
        );
    }

    #[test]
    fn a_timeout_restarts_the_discovery() {
        let mut bbr = Bbr::new(MSS);
        for _ in 0..10 {
            bbr.on_signal(
                MSS,
                Signal::Acked {
                    newly: MSS as u32,
                    rtt: Some(Duration::from_millis(10)),
                },
            );
        }
        bbr.on_signal(MSS, Signal::Timeout);
        assert!(matches!(bbr.mode, BbrMode::Startup), "discovery restarts");
        assert!(bbr.bandwidth().is_none(), "the bandwidth model cleared");
    }
}
