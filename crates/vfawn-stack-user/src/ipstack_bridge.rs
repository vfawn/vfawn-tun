// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Bridge between the synchronous `PacketDevice` contract and ipstack's
//! `AsyncRead + AsyncWrite` device abstraction.
//!
//! Two dedicated threads each own one half of the device (split through
//! `PacketDevice::duplicate`), so neither direction blocks the other:
//!
//! * the reader thread blocks in `read_batch` and pushes packets into a
//!   bounded channel that `AsyncRead` polls;
//! * the writer thread pulls from an unbounded channel that `AsyncWrite`
//!   fills and calls `write_batch` per packet.
//!
//! The bounded read channel provides natural backpressure: when ipstack is
//! slow to consume, the reader thread stalls, the kernel socket buffer
//! fills, and the sending application feels it. The unbounded write
//! direction trades memory for simplicity; the kernel TUN buffer absorbs
//! bursts well enough for the transitional period.

use bytes::BytesMut;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use vfawn_core::{DnsHijack, PacketDevice};

/// The async device that ipstack sees, plus the flag that ends the
/// bridge threads underneath it.
///
/// Stopping is not the channel's job: with no traffic the reader would
/// wait on a channel whose receiver lives inside a future that is
/// itself waiting for packets, so the loop closes on its own terms.
pub struct Bridge {
    pub io: PacketIo,
    stop: Arc<AtomicBool>,
}

impl Bridge {
    /// Signal both bridge threads to exit and release their device
    /// handles. Idempotent.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// A shareable handle to the same signal, for tasks that outlive
    /// this object's ownership of the packet io.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }
}

/// The async device that ipstack sees.
pub struct PacketIo {
    rx: mpsc::Receiver<BytesMut>,
    tx: mpsc::UnboundedSender<BytesMut>,
}

impl AsyncRead for PacketIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                let len = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..len]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "device reader closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PacketIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.tx.send(BytesMut::from(buf)) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "device writer closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Start the reader and writer threads that connect a `PacketDevice` to
/// ipstack's async world. The device is split through `duplicate`, so the
/// reader and writer each own an independent handle; closing the channels
/// stops both threads.
pub fn start(
    mut read_device: Box<dyn PacketDevice>,
    write_device: Box<dyn PacketDevice>,
    dns: Option<Arc<DnsHijack>>,
) -> Bridge {
    let (rx_tx, rx_rx) = mpsc::channel::<BytesMut>(128);
    let (tx_tx, tx_rx) = mpsc::unbounded_channel::<BytesMut>();
    let stop = Arc::new(AtomicBool::new(false));

    // Reader: blocks in read_batch, pushes one packet per channel send.
    // blocking_send stalls when the bounded channel fills up, which is the
    // intended backpressure.
    let reader_dns = dns.clone();
    let reader_stop = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("ipstack-device-reader".into())
        .spawn(move || {
            let mut bufs = vec![BytesMut::new(); 8];
            loop {
                match read_device.read_batch(&mut bufs) {
                    // A blocking device returns zero only after shutdown;
                    // an in-memory device returns zero when the queue is
                    // momentarily empty. In both cases the device is still
                    // up, so keep polling; the channel send provides the
                    // exit when the runtime drops its end.
                    Ok(0) => {
                        // A stopped device answers zero forever, and the
                        // channel only closes once the runtime stops
                        // reading; the flag is this thread's own way out.
                        if reader_stop.load(Ordering::Acquire) || rx_tx.is_closed() {
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Ok(count) => {
                        // The buffer moves into the channel: a clone here
                        // was one full-packet copy per packet on the
                        // hottest path in the process. The device refills
                        // taken buffers on the next read.
                        for buf in bufs.iter_mut().take(count) {
                            if let Some(engine) = reader_dns.as_ref() {
                                engine.hijack(buf);
                            }
                            if rx_tx.is_closed()
                                || rx_tx.blocking_send(std::mem::take(buf)).is_err()
                            {
                                return;
                            }
                        }
                    }
                    Err(_) => return,
                }
            }
        })
        .expect("spawn reader thread");

    // Writer: pulls one packet at a time from the unbounded channel.
    let writer_stop = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("ipstack-device-writer".into())
        .spawn(move || {
            let mut tx_rx = tx_rx;
            let mut write_device = write_device;
            while let Some(mut packet) = tx_rx.blocking_recv() {
                if writer_stop.load(Ordering::Acquire) {
                    return;
                }
                if let Some(engine) = dns.as_ref() {
                    engine.restore(&mut packet);
                }
                let batch = [packet];
                if write_device.write_batch(&batch).is_err() {
                    return;
                }
            }
            eprintln!("bridge writer: channel closed, exiting");
        })
        .expect("spawn writer thread");

    Bridge {
        io: PacketIo {
            rx: rx_rx,
            tx: tx_tx,
        },
        stop,
    }
}
