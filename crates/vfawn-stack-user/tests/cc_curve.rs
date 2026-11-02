// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The two congestion controllers under one scripted carrier: the same
//! growth, the same loss event, then each algorithm's answer. The
//! assertions lock the shapes that keep them distinguishable (Reno
//! halves and climbs by one window-fraction per acknowledgment, CUBIC
//! keeps more of the window and climbs on its time curve); the printed
//! series (`cargo test -- --nocapture cc_curve`) is the comparison
//! artifact the congestion-control record cites.

#![cfg(feature = "backend-native")]

use std::time::Duration;
use vfawn_stack_user::{CongestionAlgo, Cubic, Reno, Signal};

const MSS: u16 = 536;

fn one_round_trip(algo: &mut dyn CongestionAlgo) {
    // One window's worth of MSS-sized acknowledgments: a round trip at
    // the current window.
    let acks = algo.window() / u32::from(MSS);
    for _ in 0..acks {
        algo.on_signal(
            MSS,
            Signal::Acked {
                newly: u32::from(MSS),
                rtt: None,
            },
        );
    }
}

#[test]
fn the_two_algorithms_answer_one_loss_differently() {
    let mut reno: Box<dyn CongestionAlgo> = Box::new(Reno::new(MSS));
    let mut cubic: Box<dyn CongestionAlgo> = Box::new(Cubic::new(MSS));

    // Identical carriers up to the loss: slow start in lockstep.
    for _ in 0..6 {
        one_round_trip(reno.as_mut());
        one_round_trip(cubic.as_mut());
    }
    let reno_peak = reno.window();
    let cubic_peak = cubic.window();
    assert_eq!(reno_peak, cubic_peak, "identical history, identical window");
    assert!(
        reno_peak > u32::from(MSS) * 20,
        "the ramp reached a real window"
    );

    // The loss event, identical for both.
    reno.on_signal(MSS, Signal::FastRetransmit);
    cubic.on_signal(MSS, Signal::FastRetransmit);

    // First divergence: CUBIC's multiplicative decrease is gentler
    // (beta 0.7 against Reno's 0.5, RFC 9406 §4.1 against RFC 5681
    // §3.1), so it holds more of the peak.
    let reno_floor = reno.window();
    let cubic_floor = cubic.window();
    assert!(cubic_floor > reno_floor, "CUBIC keeps the larger share");

    // Reno's avoidance climb is the linear one: one round trip moves
    // the window by about one MSS, never by a slow-start doubling.
    let before = reno.window();
    one_round_trip(reno.as_mut());
    let climb = reno.window() - before;
    assert!(climb > 0, "avoidance still climbs");
    assert!(
        climb <= u32::from(MSS),
        "Reno's per-round-trip climb is one MSS, not a ramp"
    );

    // CUBIC's climb runs on wall time since the reduction (RFC 9406
    // §4.1): one reference RTT after the loss the window has moved
    // off its floor, and it still holds more than Reno does.
    std::thread::sleep(Duration::from_millis(150));
    one_round_trip(cubic.as_mut());
    assert!(
        cubic.window() > cubic_floor,
        "the time curve lifts the window off its floor"
    );
    assert!(cubic.window() > reno.window());

    // The curve table for the record: six rounds of both answers to
    // the same loss, side by side.
    eprintln!("loss answered at peak {reno_peak} bytes:");
    for round in 1..=6 {
        one_round_trip(reno.as_mut());
        std::thread::sleep(Duration::from_millis(25));
        one_round_trip(cubic.as_mut());
        eprintln!(
            "round {round}: reno {} / cubic {}",
            reno.window(),
            cubic.window()
        );
    }
}
