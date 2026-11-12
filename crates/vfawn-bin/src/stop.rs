// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! How `up` stops: the first stop request asks the worker to shut down,
//! and the orderly stop then has a deadline that a second request cuts
//! short, as sing-box's run loop and its closeMonitor shape it. The
//! requests come from a [`StopSource`], so the tests drive every branch
//! with a script instead of signals and a stuck process.

use std::fmt;
use std::future::Future;
use std::io;
use std::thread::{JoinHandle, Thread};
use std::time::Duration;

/// How long an orderly stop may take before the process leaves
/// without it: sing-box's FatalStopTimeout (constant/timeout.go:17).
pub const STOP_DEADLINE: Duration = Duration::from_secs(10);

/// Where stop requests come from.
pub trait StopSource {
    /// Resolves at the next stop request.
    fn next(&mut self) -> impl Future<Output = ()>;
}

/// The signals that stop `up`: SIGINT and SIGTERM, the pair sing-box's
/// run loop listens for (cmd_run.go: os.Interrupt, syscall.SIGTERM).
/// The streams are made once and kept, so a signal landing between two
/// waits is still counted. Making them needs the runtime's context.
pub struct StopSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl StopSignals {
    pub fn new() -> io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())?,
                terminate: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }
}

impl StopSource for StopSignals {
    async fn next(&mut self) {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.interrupt.recv() => {}
                _ = self.terminate.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// Why the orderly stop was abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutShort {
    SecondSignal,
    Deadline,
}

impl fmt::Display for CutShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CutShort::SecondSignal => "a second signal",
            CutShort::Deadline => "the stop deadline",
        })
    }
}

/// Wait for a stop request or for the worker to leave on its own (a
/// lost device), then ask it to stop through `request_stop` and wait
/// for it within `deadline`. The worker's own result comes back when it
/// finishes in time. When it does not, the caller should return from
/// main, which ends the process with the worker in it; the installed
/// handlers replaced the default action, so without the deadline a
/// stuck teardown would outlive every signal but SIGKILL.
pub fn supervise<T, S: StopSource>(
    runtime: &tokio::runtime::Runtime,
    worker: JoinHandle<T>,
    stops: &mut S,
    request_stop: impl FnOnce(&Thread),
    deadline: Duration,
) -> Result<std::thread::Result<T>, CutShort> {
    runtime.block_on(async {
        tokio::select! {
            () = stops.next() => {}
            () = finished(&worker) => {}
        }
    });

    request_stop(worker.thread());

    let cut = runtime.block_on(async {
        tokio::select! {
            // A finished worker wins every tie. Unbiased, select picks
            // a random ready branch: a process resumed past the
            // deadline (the retest's SIGSTOP run) had both ready and
            // reported a completed stop as cut short.
            biased;
            () = finished(&worker) => None,
            () = stops.next() => Some(CutShort::SecondSignal),
            () = tokio::time::sleep(deadline) => Some(CutShort::Deadline),
        }
    });
    match cut {
        Some(cause) => Err(cause),
        None => Ok(worker.join()),
    }
}

/// How often the supervisor looks at the worker.
const POLL: Duration = Duration::from_millis(200);

/// Resolves once the worker thread has returned.
async fn finished<T>(worker: &JoinHandle<T>) {
    while !worker.is_finished() {
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    /// Stop requests at scripted delays, each counted from the moment
    /// the supervisor starts waiting for it; then none ever again.
    struct Script(VecDeque<Duration>);

    impl Script {
        fn new(delays: &[u64]) -> Self {
            Self(delays.iter().copied().map(Duration::from_millis).collect())
        }
    }

    impl StopSource for Script {
        async fn next(&mut self) {
            match self.0.pop_front() {
                Some(after) => tokio::time::sleep(after).await,
                None => std::future::pending().await,
            }
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// A worker that parks until asked to stop, then takes `teardown`
    /// to finish, as `up::run` does with its drain.
    fn worker(teardown: Duration) -> (JoinHandle<u8>, Arc<AtomicBool>) {
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !seen.load(Ordering::Acquire) {
                std::thread::park();
            }
            std::thread::sleep(teardown);
            7
        });
        (handle, stop)
    }

    fn ask(stop: &AtomicBool) -> impl FnOnce(&Thread) + '_ {
        move |thread| {
            stop.store(true, Ordering::Release);
            thread.unpark();
        }
    }

    #[test]
    fn a_signal_stops_the_worker_in_time() {
        let (handle, stop) = worker(Duration::ZERO);
        let outcome = supervise(
            &runtime(),
            handle,
            &mut Script::new(&[0]),
            ask(&stop),
            STOP_DEADLINE,
        );
        assert_eq!(outcome.expect("in time").expect("no panic"), 7);
    }

    #[test]
    fn a_worker_that_leaves_on_its_own_needs_no_signal() {
        let handle = std::thread::spawn(|| 3u8);
        let outcome = supervise(
            &runtime(),
            handle,
            &mut Script::new(&[]),
            |_| {},
            STOP_DEADLINE,
        );
        assert_eq!(outcome.expect("in time").expect("no panic"), 3);
    }

    /// The deadline branch, which the retest could only reach by
    /// freezing the process: a teardown that outlasts the deadline is
    /// abandoned when the deadline passes, not when the teardown ends.
    #[test]
    fn a_stuck_stop_is_cut_at_the_deadline() {
        let (handle, stop) = worker(Duration::from_secs(30));
        let deadline = Duration::from_millis(300);
        let started = Instant::now();
        let outcome = supervise(
            &runtime(),
            handle,
            &mut Script::new(&[0]),
            ask(&stop),
            deadline,
        );
        let waited = started.elapsed();
        assert_eq!(outcome.err(), Some(CutShort::Deadline));
        assert!(waited >= deadline, "cut before the deadline: {waited:?}");
        assert!(
            waited < deadline + Duration::from_secs(2),
            "the cut waited for the teardown: {waited:?}"
        );
    }

    #[test]
    fn a_second_signal_cuts_the_stop_before_the_deadline() {
        let (handle, stop) = worker(Duration::from_secs(30));
        let started = Instant::now();
        let outcome = supervise(
            &runtime(),
            handle,
            &mut Script::new(&[0, 100]),
            ask(&stop),
            STOP_DEADLINE,
        );
        assert_eq!(outcome.err(), Some(CutShort::SecondSignal));
        assert!(started.elapsed() < STOP_DEADLINE);
    }

    /// A worker that finished while the deadline ran out reports its
    /// own result. With the deadline equal to the poll interval, both
    /// timers come due on one driver turn, the shape of a process
    /// resumed past its deadline. Unbiased, the deadline won about one
    /// run in two; the repetitions make a regression all but certain
    /// to show.
    #[test]
    fn a_finished_worker_wins_the_tie_with_the_deadline() {
        let runtime = runtime();
        for _ in 0..16 {
            let (handle, stop) = worker(Duration::from_millis(20));
            let outcome = supervise(&runtime, handle, &mut Script::new(&[0]), ask(&stop), POLL);
            assert_eq!(outcome.expect("a finished worker").expect("no panic"), 7);
        }
    }

    #[test]
    fn the_causes_read_as_the_cli_prints_them() {
        assert_eq!(CutShort::SecondSignal.to_string(), "a second signal");
        assert_eq!(CutShort::Deadline.to_string(), "the stop deadline");
    }
}
