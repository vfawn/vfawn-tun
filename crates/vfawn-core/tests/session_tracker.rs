// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Session-side accounting: every byte crossing a session handle must
//! reach the tracker, once and in the right direction, and the
//! established/closed lifecycle must be reported exactly once.
//!
//! The mock transports complete without ever yielding to an executor, so
//! a no-op waker polling once is a sufficient runtime here.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll, Waker};

use async_trait::async_trait;

use vfawn_core::{
    CloseReason, CountingTracker, FlowInfo, Network, TcpSession, TcpTransport, UdpSession,
    UdpTransport,
};

fn block_on<F: Future>(fut: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let fut = pin!(fut);
    match fut.poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("mock transport yielded, which it never does"),
    }
}

fn flow(network: Network) -> FlowInfo {
    FlowInfo {
        network,
        source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 45678)),
        destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443)),
    }
}

/// A TCP transport serving canned read chunks and accepting writes up to
/// a per-call quota, so partial accepts are observable.
struct MockTcp {
    chunks: VecDeque<Vec<u8>>,
    quota: usize,
    accepted: usize,
}

#[async_trait]
impl TcpTransport for MockTcp {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.chunks.pop_front() {
            Some(chunk) => {
                let n = chunk.len().min(buf.len());
                buf[..n].copy_from_slice(&chunk[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(self.quota);
        self.accepted += n;
        Ok(n)
    }

    async fn shutdown_write(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn abort(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A UDP transport serving one canned datagram per address.
struct MockUdp {
    datagrams: VecDeque<(Vec<u8>, SocketAddr)>,
}

#[async_trait]
impl UdpTransport for MockUdp {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.datagrams.pop_front() {
            Some((data, from)) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok((n, from))
            }
            None => Ok((
                0,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            )),
        }
    }

    async fn send(&mut self, _data: &[u8], _to: &SocketAddr) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn tcp_bytes_reach_the_tracker_in_both_directions() {
    let tracker = Arc::new(CountingTracker::new(None));
    let mut session = TcpSession::new(
        flow(Network::Tcp),
        Box::new(MockTcp {
            chunks: VecDeque::from(vec![vec![7; 10], vec![9; 15]]),
            quota: 8,
            accepted: 0,
        }),
        Some(tracker.clone()),
    );

    let mut buf = [0u8; 1500];
    assert_eq!(block_on(session.read(&mut buf)).unwrap(), 10);
    assert_eq!(block_on(session.read(&mut buf)).unwrap(), 15);
    assert_eq!(block_on(session.write(&[1; 20])).unwrap(), 8);
    assert_eq!(block_on(session.write(&[2; 5])).unwrap(), 5);

    // The counts are the exact transport returns: no estimate involved.
    assert_eq!(tracker.reverse.load(Ordering::Relaxed), 25);
    assert_eq!(tracker.forward.load(Ordering::Relaxed), 13);
}

#[test]
fn udp_datagram_lengths_reach_the_tracker() {
    let tracker = Arc::new(CountingTracker::new(None));
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 53));
    let mut session = UdpSession::new(
        flow(Network::Udp),
        Box::new(MockUdp {
            datagrams: VecDeque::from(vec![(vec![0; 40], peer), (vec![0; 12], peer)]),
        }),
        Some(tracker.clone()),
    );

    let mut buf = [0u8; 1500];
    block_on(session.recv(&mut buf)).unwrap();
    block_on(session.recv(&mut buf)).unwrap();
    block_on(session.send(&[3; 30], &peer)).unwrap();

    assert_eq!(tracker.reverse.load(Ordering::Relaxed), 52);
    assert_eq!(tracker.forward.load(Ordering::Relaxed), 30);
}

#[test]
fn establishment_is_reported_when_the_session_is_created() {
    let tracker = Arc::new(CountingTracker::new(None));
    let session = TcpSession::new(
        flow(Network::Tcp),
        Box::new(MockTcp {
            chunks: VecDeque::new(),
            quota: 8,
            accepted: 0,
        }),
        Some(tracker.clone()),
    );
    drop(session);
    assert_eq!(tracker.established.load(Ordering::Relaxed), 1);
}

#[test]
fn explicit_close_reports_once_and_drop_does_not_repeat() {
    let tracker = Arc::new(CountingTracker::new(None));
    let mut session = TcpSession::new(
        flow(Network::Tcp),
        Box::new(MockTcp {
            chunks: VecDeque::new(),
            quota: 8,
            accepted: 0,
        }),
        Some(tracker.clone()),
    );

    session.close(CloseReason::Reset);
    session.close(CloseReason::Timeout);
    drop(session);

    assert_eq!(tracker.closed.load(Ordering::Relaxed), 1);
}

#[test]
fn dropping_without_close_reports_finished() {
    let tracker = Arc::new(CountingTracker::new(None));
    let session = UdpSession::new(
        flow(Network::Udp),
        Box::new(MockUdp {
            datagrams: VecDeque::new(),
        }),
        Some(tracker.clone()),
    );
    assert_eq!(tracker.closed.load(Ordering::Relaxed), 0);
    drop(session);
    assert_eq!(tracker.closed.load(Ordering::Relaxed), 1);
}
