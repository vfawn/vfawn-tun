// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! A `PacketDevice` that echoes writes back as reads, for self-contained
//! stack round-trips without external infrastructure.
//!
//! `MockDevice` keeps the two directions separate (push/take_written);
//! `Loopback` joins them, so what the stack writes the stack reads back.
//! This is the closest in-memory analogue of a real TUN loop with a
//! kernel that routes traffic back to the same interface.

use bytes::BytesMut;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use vfawn_core::{DeviceCaps, PacketDevice};

pub struct Loopback {
    queue: Arc<Mutex<VecDeque<BytesMut>>>,
    caps: DeviceCaps,
    shutdown: Arc<AtomicBool>,
}

impl Loopback {
    pub fn new(caps: DeviceCaps) -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            caps,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Packets currently waiting to be read.
    pub fn depth(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    /// Inject a packet from outside, as if a peer sent it.
    pub fn inject(&self, packet: &[u8]) {
        self.queue.lock().unwrap().push_back(BytesMut::from(packet));
    }
}

impl PacketDevice for Loopback {
    fn read_batch(&mut self, bufs: &mut [BytesMut]) -> io::Result<usize> {
        if self.shutdown.load(Ordering::Acquire) {
            return Ok(0);
        }
        let mut queue = self.queue.lock().unwrap();
        let mut count = 0;
        for slot in bufs.iter_mut() {
            let Some(packet) = queue.pop_front() else {
                break;
            };
            *slot = packet;
            count += 1;
        }
        Ok(count)
    }

    fn write_batch(&mut self, bufs: &[BytesMut]) -> io::Result<usize> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "device is down",
            ));
        }
        let mut queue = self.queue.lock().unwrap();
        for buf in bufs {
            queue.push_back(buf.clone());
        }
        Ok(bufs.len())
    }

    fn capabilities(&self) -> DeviceCaps {
        self.caps
    }

    fn shutdown(&self) -> io::Result<()> {
        self.shutdown.store(true, Ordering::Release);
        Ok(())
    }

    fn duplicate(&self) -> io::Result<Box<dyn PacketDevice>> {
        Ok(Box::new(Loopback {
            queue: Arc::clone(&self.queue),
            caps: self.caps,
            shutdown: Arc::clone(&self.shutdown),
        }))
    }
}
