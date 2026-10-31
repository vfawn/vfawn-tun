// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Sessions, flow verdicts and flow tracking.
//!
//! [`SessionHandler`] is the single business boundary between this library
//! and the host: the host decides the fate of every flow and consumes every
//! terminated session, while the library never learns what the host does
//! with them.

use async_trait::async_trait;
use bytes::Bytes;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Transport protocol of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Network {
    Tcp,
    Udp,
    Icmp,
}

/// The identity of a flow as captured from the device.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowInfo {
    pub network: Network,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// What happens to a flow whose first packet was just seen.
#[non_exhaustive]
pub enum Verdict {
    /// Terminate the flow and hand a session to the host.
    Accept,
    /// Refuse the flow on the wire: TCP RST, ICMP unreachable for the
    /// datagram protocols.
    Reject,
    /// Discard silently and count.
    Drop,
    /// Bypass means three different physical acts depending on where it is
    /// returned:
    ///
    /// * from route-rule evaluation: a genuine pass-through, the prefix is
    ///   never captured into the device in the first place;
    /// * from [`SessionHandler::judge_flow`] under a user-space stack: the
    ///   packet has already left the kernel, and writing it back would loop;
    ///   the flow takes the normal accept path and the host connects
    ///   directly itself;
    /// * in the kernel-NAT context: skip the capture rule for this flow,
    ///   which is a genuine pass-through implemented another way.
    Bypass,
    /// Terminate the flow but present the rewritten destination to the host.
    Redirect(SocketAddr),
    /// Like [`Verdict::Accept`], with per-flow overrides.
    AcceptWith {
        /// Idle timeout for UDP flows; `None` keeps the configured default.
        udp_timeout: Option<Duration>,
        /// Per-flow accounting hook.
        tracker: Option<Arc<dyn FlowTrackerHook>>,
    },
}

impl std::fmt::Debug for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept => f.write_str("Accept"),
            Self::Reject => f.write_str("Reject"),
            Self::Drop => f.write_str("Drop"),
            Self::Bypass => f.write_str("Bypass"),
            Self::Redirect(addr) => write!(f, "Redirect({addr})"),
            Self::AcceptWith {
                udp_timeout,
                tracker,
            } => write!(
                f,
                "AcceptWith {{ udp_timeout: {udp_timeout:?}, tracker: {} }}",
                tracker.is_some()
            ),
        }
    }
}

/// What to do with an ICMP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Hand it to the kernel side of the stack.
    Forward,
    /// Answer locally (echo requests).
    Reply,
    /// Discard silently.
    Drop,
}

/// Why a flow ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// Reset by either side.
    Reset,
    /// Both directions closed cleanly.
    Finished,
    /// Idle past the configured timeout.
    Timeout,
    /// An ICMP error about this flow arrived; the value is the ICMP code.
    IcmpError(u8),
}

/// Per-flow byte accounting, reported while the flow is alive.
pub trait FlowTrackerHook: Send + Sync {
    /// Bytes counted from the captured side toward the host's outbound.
    fn count_forward(&self, n: u64);
    /// Bytes counted on the way back in.
    fn count_reverse(&self, n: u64);
    /// The flow completed establishment (TCP handshake done, first
    /// datagram exchanged).
    fn established(&self);
    /// The flow ended for the given reason; no further calls after this.
    fn closed(&self, reason: CloseReason);
}

/// Byte-stream side of a terminated TCP flow.
///
/// Half-close is a first-class operation: proxies need to propagate FIN in
/// one direction while the other stays open.
#[async_trait]
pub trait TcpTransport: Send {
    /// Read up to `buf.len()` bytes. `Ok(0)` means the peer closed its
    /// write side; reads may still follow nothing further.
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// Write as much as the send buffer accepts.
    async fn write(&mut self, data: &[u8]) -> io::Result<usize>;
    /// Send our FIN; the read direction stays open.
    async fn shutdown_write(&mut self) -> io::Result<()>;
    /// Abort the flow; emits RST on the wire where applicable.
    async fn abort(&mut self) -> io::Result<()>;
}

/// Datagram side of a terminated UDP flow.
#[async_trait]
pub trait UdpTransport: Send {
    /// Receive one datagram, returning its length and the remote it came
    /// from.
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    /// Send one datagram to the given remote.
    async fn send(&mut self, data: &[u8], to: &SocketAddr) -> io::Result<()>;
}

/// A terminated TCP flow handed to the host.
pub struct TcpSession {
    flow: FlowInfo,
    transport: Box<dyn TcpTransport>,
    tracker: Option<Arc<dyn FlowTrackerHook>>,
    close_reported: bool,
}

impl TcpSession {
    /// Assemble a session from its parts. Called by the backend that
    /// terminated the flow, which by contract only happens once the
    /// handshake is complete; the tracker hears `established` here.
    pub fn new(
        flow: FlowInfo,
        transport: Box<dyn TcpTransport>,
        tracker: Option<Arc<dyn FlowTrackerHook>>,
    ) -> Self {
        if let Some(ref t) = tracker {
            t.established();
        }
        Self {
            flow,
            transport,
            tracker,
            close_reported: false,
        }
    }

    /// The captured five-tuple of this flow.
    pub fn flow(&self) -> &FlowInfo {
        &self.flow
    }

    /// The accounting hook installed for this flow, if any.
    pub fn tracker(&self) -> Option<&Arc<dyn FlowTrackerHook>> {
        self.tracker.as_ref()
    }

    /// See [`TcpTransport::read`]. Bytes read count toward the reverse
    /// direction of the flow.
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.transport.read(buf).await?;
        if n > 0
            && let Some(ref t) = self.tracker
        {
            t.count_reverse(n as u64);
        }
        Ok(n)
    }

    /// See [`TcpTransport::write`]. Bytes accepted count toward the
    /// forward direction of the flow.
    pub async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = self.transport.write(data).await?;
        if n > 0
            && let Some(ref t) = self.tracker
        {
            t.count_forward(n as u64);
        }
        Ok(n)
    }

    /// See [`TcpTransport::shutdown_write`].
    pub async fn shutdown_write(&mut self) -> io::Result<()> {
        self.transport.shutdown_write().await
    }

    /// See [`TcpTransport::abort`].
    pub async fn abort(&mut self) -> io::Result<()> {
        self.transport.abort().await
    }

    /// Report the flow closed for `reason`, exactly once. A session
    /// dropped without this reports `CloseReason::Finished`.
    pub fn close(&mut self, reason: CloseReason) {
        if !self.close_reported {
            self.close_reported = true;
            if let Some(ref t) = self.tracker {
                t.closed(reason);
            }
        }
    }
}

impl Drop for TcpSession {
    fn drop(&mut self) {
        self.close(CloseReason::Finished);
    }
}

/// A terminated UDP flow handed to the host.
pub struct UdpSession {
    flow: FlowInfo,
    transport: Box<dyn UdpTransport>,
    tracker: Option<Arc<dyn FlowTrackerHook>>,
    close_reported: bool,
}

impl UdpSession {
    /// Assemble a session from its parts. Called by the backend that
    /// terminated the flow, which happens with the first datagram of the
    /// flow in hand; the tracker hears `established` here.
    pub fn new(
        flow: FlowInfo,
        transport: Box<dyn UdpTransport>,
        tracker: Option<Arc<dyn FlowTrackerHook>>,
    ) -> Self {
        if let Some(ref t) = tracker {
            t.established();
        }
        Self {
            flow,
            transport,
            tracker,
            close_reported: false,
        }
    }

    /// The captured five-tuple of this flow.
    pub fn flow(&self) -> &FlowInfo {
        &self.flow
    }

    /// The accounting hook installed for this flow, if any.
    pub fn tracker(&self) -> Option<&Arc<dyn FlowTrackerHook>> {
        self.tracker.as_ref()
    }

    /// See [`UdpTransport::recv`]. The datagram length counts toward
    /// the reverse direction of the flow.
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, from) = self.transport.recv(buf).await?;
        if n > 0
            && let Some(ref t) = self.tracker
        {
            t.count_reverse(n as u64);
        }
        Ok((n, from))
    }

    /// See [`UdpTransport::send`]. Bytes sent count toward the forward
    /// direction of the flow.
    pub async fn send(&mut self, data: &[u8], to: &SocketAddr) -> io::Result<()> {
        self.transport.send(data, to).await?;
        if !data.is_empty()
            && let Some(ref t) = self.tracker
        {
            t.count_forward(data.len() as u64);
        }
        Ok(())
    }

    /// Report the flow closed for `reason`, exactly once. A session
    /// dropped without this reports `CloseReason::Finished`.
    pub fn close(&mut self, reason: CloseReason) {
        if !self.close_reported {
            self.close_reported = true;
            if let Some(ref t) = self.tracker {
                t.closed(reason);
            }
        }
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.close(CloseReason::Finished);
    }
}

/// An ICMP packet handed to the host.
pub struct IcmpPacket {
    flow: FlowInfo,
    kind: u8,
    code: u8,
    payload: Bytes,
}

impl IcmpPacket {
    /// Wrap a captured ICMP packet.
    pub fn new(flow: FlowInfo, kind: u8, code: u8, payload: Bytes) -> Self {
        Self {
            flow,
            kind,
            code,
            payload,
        }
    }

    /// The captured flow identity.
    pub fn flow(&self) -> &FlowInfo {
        &self.flow
    }

    /// ICMP type field.
    pub fn kind(&self) -> u8 {
        self.kind
    }

    /// ICMP code field.
    pub fn code(&self) -> u8 {
        self.code
    }

    /// Payload after the ICMP header.
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }
}

/// The host side of the library: decides the fate of flows and consumes
/// every terminated session.
#[async_trait]
pub trait SessionHandler: Send + Sync {
    /// Decide the fate of a flow from its first packet.
    ///
    /// Called synchronously on the data-plane thread that owns the flow.
    /// It must stay in the microsecond range, must not block, and must not
    /// call back into the library from the same thread: a slow callback
    /// stalls its flow and its shard, which is the intended backpressure
    /// rather than a defect.
    ///
    /// `first_packet` carries a payload for UDP flows only; a TCP SYN has
    /// nothing to show.
    fn judge_flow(&self, flow: &FlowInfo, first_packet: &[u8]) -> Verdict;

    /// A TCP flow passed judgment and is now a readable, writable stream.
    async fn on_tcp(&self, session: TcpSession);

    /// A UDP flow passed judgment and is now a datagram exchange.
    async fn on_udp(&self, session: UdpSession);

    /// An ICMP packet arrived for a flow that passed judgment.
    async fn on_icmp(&self, packet: IcmpPacket) -> Action;
}
