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
//!
//! Every TCP frame crossing [`PacketIo`] is shown to [`LiveFlows`], so the
//! stop can reset the flows ipstack leaves open. The stop runs in
//! sing-tun's order (stack_gvisor.go:131-135): detach, reset, then close.
//! [`Teardown`] seals the table, queues the resets behind everything
//! ipstack already wrote, and ends the queue; the writer writes it out
//! and only then shuts the device down.

use bytes::BytesMut;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use vfawn_core::{DnsHijack, PacketDevice};

use crate::live_flows::LiveFlows;
use crate::syn_gate::{GateOutcome, SynGate};

/// The async device that ipstack sees, the flows it holds open, and
/// the stop that ends the bridge threads underneath it.
pub struct Bridge {
    pub io: PacketIo,
    pub flows: Arc<LiveFlows>,
    pub teardown: Teardown,
}

/// The bridge's stop. Stopping is not the channel's job: with no
/// traffic the reader would wait on a channel whose receiver lives
/// inside a future that is itself waiting for packets, so the loop
/// closes on its own terms.
///
/// Runs on drop too, so a stack that unwinds still closes its device.
pub struct Teardown {
    stop: Arc<AtomicBool>,
    flows: Arc<LiveFlows>,
    tx: mpsc::UnboundedSender<BytesMut>,
}

impl Teardown {
    /// Reset the live flows, then close the device once the writer has
    /// put every queued frame and the resets on the wire.
    pub fn finish(self) {}
}

impl Drop for Teardown {
    fn drop(&mut self) {
        // Set first: the device going down under the reader is the stop,
        // not a lost device.
        self.stop.store(true, Ordering::Release);
        for reset in self.flows.seal() {
            let _ = self.tx.send(BytesMut::from(&reset[..]));
        }
        let _ = self.tx.send(BytesMut::new());
    }
}

/// The async device that ipstack sees.
pub struct PacketIo {
    rx: mpsc::Receiver<BytesMut>,
    tx: mpsc::UnboundedSender<BytesMut>,
    flows: Arc<LiveFlows>,
}

impl AsyncRead for PacketIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                self.flows.inbound(&packet);
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
        // The empty frame is the writer's end marker; ipstack never
        // writes one, and must not end the queue by accident.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self
            .flows
            .outbound(buf, || self.tx.send(BytesMut::from(buf)))
        {
            Some(Ok(())) => Poll::Ready(Ok(buf.len())),
            Some(Err(_)) | None => Poll::Ready(Err(io::Error::new(
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
/// reader and writer each own an independent handle; [`Teardown`] stops
/// both threads.
pub fn start(
    mut read_device: Box<dyn PacketDevice>,
    write_device: Box<dyn PacketDevice>,
    dns: Option<Arc<DnsHijack>>,
    broadcast: Option<std::net::Ipv4Addr>,
    gate: Option<Arc<SynGate>>,
    stack: vfawn_core::StackHandle,
) -> Bridge {
    let (rx_tx, rx_rx) = mpsc::channel::<BytesMut>(128);
    let (tx_tx, tx_rx) = mpsc::unbounded_channel::<BytesMut>();
    let stop = Arc::new(AtomicBool::new(false));
    let flows = Arc::new(LiveFlows::default());

    // Reader: blocks in read_batch, pushes one packet per channel send.
    // blocking_send stalls when the bounded channel fills up, which is the
    // intended backpressure.
    let reader_dns = dns.clone();
    let reader_stop = Arc::clone(&stop);
    // The gate's answers (resets for refused SYNs) leave through the
    // writer like every frame ipstack emits, so the DNS rewrite undoes
    // itself on them too.
    let answers = tx_tx.clone();
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
                            // The network's housekeeping never becomes
                            // a flow (sing-tun's dropNonUnicast).
                            if !vfawn_wire::flow::is_unicast_destination(buf, broadcast) {
                                continue;
                            }
                            if let Some(engine) = reader_dns.as_ref() {
                                engine.hijack(buf);
                            }
                            match gate.as_ref().map(|gate| gate.inspect(buf)) {
                                None | Some(GateOutcome::Pass) => {}
                                Some(GateOutcome::Swallow) => continue,
                                Some(GateOutcome::Answer(frame)) => {
                                    let _ = answers.send(BytesMut::from(&frame[..]));
                                    continue;
                                }
                            }
                            if rx_tx.is_closed()
                                || rx_tx.blocking_send(std::mem::take(buf)).is_err()
                            {
                                return;
                            }
                        }
                    }
                    // The device died under the bridge: the stack stops
                    // with the reason, and the runtime's stop watch
                    // takes the rest down.
                    Err(error) => {
                        if !reader_stop.load(Ordering::Acquire) && stack.fail(error.to_string()) {
                            eprintln!("vfawn: device lost, stack stopped: {error}");
                        }
                        return;
                    }
                }
            }
        })
        .expect("spawn reader thread");

    // Writer: pulls one packet at a time from the unbounded channel until
    // the teardown's end marker, then shuts the device down. The shutdown
    // is the writer's so it lands after the last reset, never before.
    std::thread::Builder::new()
        .name("ipstack-device-writer".into())
        .spawn(move || {
            let mut tx_rx = tx_rx;
            let mut write_device = write_device;
            // A failed write ends the writing, as it always has, but not
            // the wait: the device stays up until the teardown says so.
            let mut writing = true;
            while let Some(mut packet) = tx_rx.blocking_recv() {
                if packet.is_empty() {
                    break;
                }
                if !writing {
                    continue;
                }
                if let Some(engine) = dns.as_ref() {
                    engine.restore(&mut packet);
                }
                let mut batch = [packet];
                writing = write_device.write_batch(&mut batch).is_ok();
            }
            let _ = write_device.shutdown();
        })
        .expect("spawn writer thread");

    Bridge {
        io: PacketIo {
            rx: rx_rx,
            tx: tx_tx.clone(),
            flows: Arc::clone(&flows),
        },
        flows: Arc::clone(&flows),
        teardown: Teardown {
            stop,
            flows,
            tx: tx_tx,
        },
    }
}
