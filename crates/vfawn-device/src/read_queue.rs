// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The read hand-off between a device's I/O thread and its reader.
//!
//! sing-tun's reader takes packets straight from the device: gVisor's
//! dispatch loop reads the Wintun ring (`tun_windows_gvisor.go:67-95`)
//! or the descriptor, so a slow stack leaves the backlog in the
//! kernel's queue, which is the only place anything is dropped. Ours
//! puts a bounded channel between the I/O thread and the reader. When
//! that channel is full, the I/O thread holds what it read and reads
//! nothing more until the reader makes room. The backlog stays in the
//! kernel's queue as it does under sing-tun, instead of frames being
//! thrown away here with that queue still mostly free (N-11 of the
//! Windows retest).

use std::collections::VecDeque;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::thread::{self, Thread};
use std::time::Duration;

use bytes::BytesMut;

/// How long a reader with nothing in hand waits for a batch before it
/// answers zero: callers loop on zero, and an unbounded block would
/// hang every poll-style reader past its own deadline.
const READ_WAIT: Duration = Duration::from_millis(50);

/// The longest a held batch waits between retries when no wake comes:
/// a backstop only, since the reader, the writers and the shutdown
/// all wake the I/O thread themselves.
const HOLD_PARK: Duration = Duration::from_millis(10);

/// What became of a batch offered to the reader.
pub(crate) enum Delivery {
    Sent,
    /// The channel is full; the batch comes back to be held.
    Held(Vec<BytesMut>),
    /// The reader is gone; nothing will ever take the batch.
    Gone,
}

/// The I/O thread's side of a full channel: whether it holds a batch,
/// and how to wake it once there is room.
#[derive(Default)]
pub(crate) struct Backlog {
    backlogged: AtomicBool,
    io_thread: OnceLock<Thread>,
}

impl Backlog {
    /// Called once on the I/O thread, before it first delivers.
    pub(crate) fn register(&self) {
        let _ = self.io_thread.set(thread::current());
    }

    /// Offer `frames` to the reader, never blocking.
    pub(crate) fn deliver(
        &self,
        reads: &SyncSender<Vec<BytesMut>>,
        frames: Vec<BytesMut>,
    ) -> Delivery {
        let frames = match reads.try_send(frames) {
            Ok(()) => {
                if self.backlogged.load(Ordering::Relaxed) {
                    self.backlogged.store(false, Ordering::SeqCst);
                }
                return Delivery::Sent;
            }
            Err(TrySendError::Disconnected(_)) => return Delivery::Gone,
            Err(TrySendError::Full(frames)) => frames,
        };
        // Raised before the second try: a reader that makes room after
        // this point sees the flag and wakes us, so the park that
        // follows a hold never sleeps through the room it waits for.
        self.backlogged.store(true, Ordering::SeqCst);
        match reads.try_send(frames) {
            Ok(()) => {
                self.backlogged.store(false, Ordering::SeqCst);
                Delivery::Sent
            }
            Err(TrySendError::Full(frames)) => Delivery::Held(frames),
            Err(TrySendError::Disconnected(_)) => Delivery::Gone,
        }
    }

    /// Park the I/O thread while it holds a batch. A wake ends it.
    pub(crate) fn wait(&self) {
        thread::park_timeout(HOLD_PARK);
    }

    /// Wake the I/O thread if it holds a batch: the reader after it
    /// made room, a writer with work, or a shutdown.
    pub(crate) fn wake(&self) {
        if self.backlogged.load(Ordering::SeqCst)
            && let Some(io_thread) = self.io_thread.get()
        {
            io_thread.unpark();
        }
    }
}

/// Fill `bufs` from what an earlier call left over, then from the
/// channel. Only an empty hand waits; once a frame is served the rest
/// is whatever is already queued. A batch larger than the caller's
/// buffers keeps its tail in `leftover` for the next call instead of
/// losing it. Answers how many buffers were filled.
pub(crate) fn fill(
    reads: &Receiver<Vec<BytesMut>>,
    leftover: &mut VecDeque<BytesMut>,
    bufs: &mut [BytesMut],
) -> usize {
    let mut served = 0;
    while served < bufs.len() {
        if leftover.is_empty() {
            let batch = if served == 0 {
                reads.recv_timeout(READ_WAIT).ok()
            } else {
                reads.try_recv().ok()
            };
            match batch {
                Some(batch) => leftover.extend(batch),
                None => break,
            }
        }
        let Some(frame) = leftover.pop_front() else {
            break;
        };
        bufs[served] = frame;
        served += 1;
    }
    served
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::Instant;

    fn frame(tag: u8) -> BytesMut {
        BytesMut::from(&[tag][..])
    }

    fn batch(tags: std::ops::Range<u8>) -> Vec<BytesMut> {
        tags.map(frame).collect()
    }

    #[test]
    fn a_batch_wider_than_the_caller_loses_nothing() {
        let (tx, rx) = mpsc::sync_channel(4);
        tx.send(batch(0..20)).unwrap();
        let mut leftover = VecDeque::new();
        let mut bufs = vec![BytesMut::new(); 8];
        let mut seen = Vec::new();
        for expected in [8, 8, 4] {
            assert_eq!(fill(&rx, &mut leftover, &mut bufs), expected);
            seen.extend(bufs.iter().take(expected).map(|b| b[0]));
        }
        assert_eq!(seen, (0..20).collect::<Vec<u8>>(), "in order, none lost");
    }

    #[test]
    fn several_queued_batches_fill_one_call() {
        let (tx, rx) = mpsc::sync_channel(8);
        for tag in 0..5 {
            tx.send(vec![frame(tag)]).unwrap();
        }
        let mut leftover = VecDeque::new();
        let mut bufs = vec![BytesMut::new(); 8];
        assert_eq!(fill(&rx, &mut leftover, &mut bufs), 5);
    }

    #[test]
    fn a_partial_hand_returns_without_waiting() {
        let (_tx, rx) = mpsc::sync_channel::<Vec<BytesMut>>(1);
        let mut leftover: VecDeque<BytesMut> = batch(0..3).into();
        let mut bufs = vec![BytesMut::new(); 8];
        let started = Instant::now();
        assert_eq!(fill(&rx, &mut leftover, &mut bufs), 3);
        assert!(started.elapsed() < READ_WAIT, "served frames never wait");
    }

    #[test]
    fn a_full_channel_holds_and_the_reader_releases_it() {
        let (tx, rx) = mpsc::sync_channel(1);
        let backlog = Arc::new(Backlog::default());
        assert!(matches!(backlog.deliver(&tx, batch(0..1)), Delivery::Sent));

        // The I/O thread: holds while full, parks, and delivers once
        // the reader wakes it.
        let io = {
            let backlog = Arc::clone(&backlog);
            thread::spawn(move || {
                backlog.register();
                let mut held = batch(1..2);
                loop {
                    match backlog.deliver(&tx, held) {
                        Delivery::Sent => return,
                        Delivery::Held(frames) => {
                            held = frames;
                            backlog.wait();
                        }
                        Delivery::Gone => panic!("the reader is still here"),
                    }
                }
            })
        };
        let mut leftover = VecDeque::new();
        let mut bufs = vec![BytesMut::new(); 1];
        let mut seen = Vec::new();
        while seen.len() < 2 {
            if fill(&rx, &mut leftover, &mut bufs) == 1 {
                seen.push(bufs[0][0]);
                backlog.wake();
            }
        }
        io.join().unwrap();
        assert_eq!(seen, vec![0, 1], "the held batch arrives, in order");
        assert!(!backlog.backlogged.load(Ordering::SeqCst));
    }

    #[test]
    fn a_reader_gone_is_reported() {
        let (tx, rx) = mpsc::sync_channel(1);
        drop(rx);
        let backlog = Backlog::default();
        assert!(matches!(backlog.deliver(&tx, batch(0..1)), Delivery::Gone));
    }
}
