// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Termination through the ipstack crate.
//!
//! Transitional backend: it exists so the framework, the benchmark harness
//! and the host-facing API are all exercisable while the in-house TCP
//! implementation is being written. Every touch point here is replaceable
//! without touching callers, because everything crosses the
//! `StackBackend` and `SessionHandler` contracts.
//!
//! What this backend does not do, honestly stated:
//!
//! * no SYN cookies, no accept-queue bounding;
//! * no congestion control beyond the stack default;
//! * ICMP arrives as raw payloads with no differentiation between echo
//!   requests and error reports.
//!
//! None of these are hidden; they are the gap the in-house stack fills.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vfawn_core::{
    DnsHijack, FlowInfo, FlowTrackerHook, IcmpPacket, Network, PacketDevice, SessionHandler,
    StackBackend, StackHandle, TcpSession, TcpTransport, UdpNat, UdpSession, UdpSessionMode,
    UdpTransport, Verdict,
};

use crate::ipstack_bridge;

/// Configuration for the transitional ipstack backend.
#[derive(Clone)]
pub struct IpstackBackend {
    /// Maximum segment size; derived from the device MTU when zero.
    pub mss: u16,
    /// The NAT table UDP flows are registered in. Shared with the
    /// runtime's sweep task, which expires idle mappings and reports
    /// their close to the flow trackers.
    pub udp_nat: Arc<UdpNat>,
    /// The DNS rewrite engine carried by the device bridge. An engine
    /// with no virtual addresses leaves every packet alone.
    pub dns: Arc<DnsHijack>,
    /// Idle timeout for UDP sessions, in seconds.
    pub udp_timeout_secs: u64,
    /// TCP connection timeout, in seconds.
    pub tcp_timeout_secs: u64,
}

impl Default for IpstackBackend {
    fn default() -> Self {
        Self {
            mss: 1460,
            udp_nat: Arc::new(UdpNat::new(
                UdpSessionMode::Symmetric,
                std::time::Duration::from_secs(300),
                0,
            )),
            dns: Arc::new(DnsHijack::new(None, None)),
            udp_timeout_secs: 300,
            tcp_timeout_secs: 60,
        }
    }
}

impl StackBackend for IpstackBackend {
    fn spawn(
        self: Box<Self>,
        device: Box<dyn PacketDevice>,
        handler: Arc<dyn SessionHandler>,
    ) -> io::Result<StackHandle> {
        let handle = StackHandle::new();
        let write_device = device.duplicate()?;
        // A third handle whose only job is closing the device when the
        // runtime stops: the bridge halves live inside their threads,
        // and the TUN interface only disappears once every fd is gone,
        // which a restart that recreates it by name depends on.
        let closer = device.duplicate()?;
        let sweep_closer = device.duplicate()?;
        let bridge = ipstack_bridge::start(device, write_device, Some(Arc::clone(&self.dns)));
        let bridge_stopper = bridge.stop_flag();

        // The builder returns &mut Self; the final take gives ownership
        // back for the move into the runtime thread.
        let config = {
            let mut builder = IpStackConfig::default();
            builder.mtu = self.mss + 40;
            builder.udp_timeout(std::time::Duration::from_secs(self.udp_timeout_secs));
            builder
        };

        let stop = handle.clone();
        let udp_nat = Arc::clone(&self.udp_nat);
        std::thread::Builder::new()
            .name("ipstack-runtime".into())
            .spawn(move || {
                // A panic in the runtime (a misbehaving handler, a stack
                // bug) must not take the process down; the stop flag still
                // works from outside, so shutdown remains reachable.
                // The runtime moves into a slot so the teardown path can
                // hand it to a bystander thread even after a panic.
                let runtime_slot: std::sync::Mutex<Option<tokio::runtime::Runtime>> =
                    std::sync::Mutex::new(None);
                let runtime_slot = std::sync::Arc::new(runtime_slot);
                let slot_for_body = std::sync::Arc::clone(&runtime_slot);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    // Multi-thread, not current-thread: ipstack stream
                    // teardown calls `block_in_place` on drop, which the
                    // current-thread flavor rejects outright.
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                        .expect("ipstack runtime");
                    // The runtime lives in the slot so the teardown path
                    // can hand it to a bystander thread; the guard holds
                    // it here for the duration of the block_on.
                    let mut guard = slot_for_body.lock().unwrap();
                    *guard = Some(rt);
                    guard.as_ref().unwrap().block_on(async move {
                        // Idle NAT mappings must not wait for the next
                        // datagram to be reclaimed; a one-second sweep
                        // keeps close reports flowing on quiet tables.
                        let sweep_table = Arc::clone(&udp_nat);
                        let sweep_stop = stop.clone();
                        tokio::spawn(async move {
                            use std::sync::atomic::Ordering;
                            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
                            loop {
                                tick.tick().await;
                                if sweep_stop.is_stopped() {
                                    // The accept loop only notices the stop
                                    // between streams, and with no traffic
                                    // that is never; closing the device is
                                    // what actually unwinds it, which also
                                    // frees the interface for a restart.
                                    bridge_stopper.store(true, Ordering::Release);
                                    let _ = sweep_closer.shutdown();
                                    break;
                                }
                                sweep_table.sweep(std::time::Instant::now());
                            }
                        });

                        let mut stack = IpStack::new(config, bridge.io);
                        loop {
                            // ipstack's accept has no stop side; waiting
                            // for it to notice a closed device is what
                            // kept whole process runs holding their fds.
                            // The watcher races it and cancels the wait.
                            tokio::select! {
                                _ = stop_watcher(&stop) => break,
                                accepted = stack.accept() => match accepted {
                                    Ok(stream) => {
                                        // One task per stream: a flow
                                        // that wedges in dispatch must
                                        // cost itself, not the accept
                                        // loop and every flow behind it.
                                        let handler = Arc::clone(&handler);
                                        let udp_nat = Arc::clone(&udp_nat);
                                        tokio::spawn(async move {
                                            dispatch(stream, &handler, &udp_nat).await
                                        });
                                    }
                                    Err(_) => break,
                                },
                            }
                        }
                    });
                    // Wake the bridge threads out of their device reads
                    // so the fds close and the interface can be recreated.
                    let _ = closer.shutdown();
                }));

                if let Err(panic) = outcome {
                    eprintln!(
                        "ipstack runtime contained a panic: {}",
                        panic
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("unknown")
                    );
                }

                // Dropping a multi-thread runtime from a thread inside
                // it waits for the runtime's own workers and never
                // finishes; retiring it on a bystander thread lets this
                // thread and every bridge thread exit for real.
                if let Some(rt) = runtime_slot.lock().unwrap().take() {
                    std::thread::spawn(move || drop(rt));
                }
            })?;

        Ok(handle)
    }
}

/// Resolve once the handle is stopped, polling gently; exists to be
/// cancelled by `select` against a wait that has no stop of its own.
async fn stop_watcher(handle: &vfawn_core::StackHandle) {
    loop {
        if handle.is_stopped() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// Run the host's synchronous verdict callback with panic containment:
/// a panicking host loses this one flow, not the data plane.
///
/// The callback runs inline on the stream's dispatch path, so its runtime
/// is also a backpressure signal: a callback that stalls delays exactly
/// its own flow, which the contract makes a host-visible property.
fn judged(handler: &Arc<dyn SessionHandler>, flow: &FlowInfo) -> Option<Verdict> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handler.judge_flow(flow, &[])
    }))
    .map_err(|_| eprintln!("judge_flow panicked for {flow:?}; flow dropped"))
    .ok()
}

/// Route one accepted stream to the appropriate handler callback.
async fn dispatch(stream: IpStackStream, handler: &Arc<dyn SessionHandler>, udp_nat: &Arc<UdpNat>) {
    match stream {
        IpStackStream::Tcp(tcp) => {
            let local = tcp.local_addr();
            let peer = tcp.peer_addr();
            let flow = FlowInfo {
                network: Network::Tcp,
                source: local,
                destination: peer,
            };
            // A SYN carries no payload; the handler sees an empty first
            // packet, which matches the contract.
            let Some(verdict) = judged(handler, &flow) else {
                return;
            };
            let action = vfawn_core::verdict::execute(verdict, &flow);
            match action {
                vfawn_core::VerdictAction::CreateSession { tracker, .. } => {
                    let transport = Box::new(TcpIo { stream: tcp });
                    let tracker = tracker.map(|t| t as Arc<dyn FlowTrackerHook>);
                    let session = TcpSession::new(flow, transport, tracker);
                    handler.on_tcp(session).await;
                }
                vfawn_core::VerdictAction::Drop | vfawn_core::VerdictAction::Reset => {
                    // Refused flows close politely. Dropping the stream
                    // where it stands made ipstack's teardown block its
                    // own accept loop, wedging every later flow with it;
                    // a shutdown drains through its state machine. A
                    // crafted RST arrives with the in-house stack.
                    use tokio::io::AsyncWriteExt;
                    let mut tcp = tcp;
                    let _ = tcp.shutdown().await;
                }
                vfawn_core::VerdictAction::RedirectTo(_) => {
                    // Destination rewriting is not possible inside the
                    // transitional ipstack backend; the in-house stack
                    // will handle it.
                }
            }
        }
        IpStackStream::Udp(udp) => {
            let local = udp.local_addr();
            let peer = udp.peer_addr();
            let flow = FlowInfo {
                network: Network::Udp,
                source: local,
                destination: peer,
            };
            let Some(verdict) = judged(handler, &flow) else {
                return;
            };
            let action = vfawn_core::verdict::execute(verdict, &flow);
            match action {
                vfawn_core::VerdictAction::CreateSession {
                    udp_timeout_override,
                    tracker,
                } => {
                    // The NAT table hears about the flow before the host
                    // does, so return traffic has a path to travel the
                    // moment the session exists.
                    let tracker = tracker.map(|t| t as Arc<dyn FlowTrackerHook>);
                    udp_nat.on_outbound(
                        flow.source,
                        flow.destination,
                        tracker.clone(),
                        udp_timeout_override,
                        std::time::Instant::now(),
                    );
                    let transport = Box::new(UdpIo {
                        stream: udp,
                        nat: Arc::clone(udp_nat),
                        source: flow.source,
                    });
                    let session = UdpSession::new(flow, transport, tracker);
                    handler.on_udp(session).await;
                }
                _ => {
                    // Drop, Reset, and Redirect all discard the stream in
                    // the transitional backend.
                }
            }
        }
        IpStackStream::UnknownTransport(unknown) => {
            // ICMP and other IP protocols arrive here as raw payloads.
            // The handler gets the payload and a best-effort flow identity;
            // the return action is honored only for Drop (skip delivery).
            let protocol = unknown.ip_protocol();
            if protocol.0 == 1 || protocol.0 == 58 {
                // ICMP or ICMPv6
                let flow = FlowInfo {
                    network: Network::Icmp,
                    source: SocketAddr::new(unknown.src_addr(), 0),
                    destination: SocketAddr::new(unknown.dst_addr(), 0),
                };
                let payload = unknown.payload().to_vec();
                if payload.len() >= 4 {
                    let packet =
                        IcmpPacket::new(flow, payload[0], payload[1], bytes::Bytes::from(payload));
                    let action = handler.on_icmp(packet).await;
                    // Reply and Forward need wire-level emission that this
                    // backend does not implement; only Drop is effective
                    // (by doing nothing). This limitation is the primary
                    // reason the backend is transitional.
                    let _ = action;
                }
            }
        }
        IpStackStream::UnknownNetwork(_) => {
            // Unparseable at the IP layer; nothing sensible to do.
        }
    }
}

/// TCP session adapter: our `TcpTransport` implemented over ipstack's
/// async stream.
struct TcpIo {
    stream: IpStackTcpStream,
}

#[async_trait]
impl TcpTransport for TcpIo {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf).await
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.stream.write(data).await
    }

    async fn shutdown_write(&mut self) -> io::Result<()> {
        self.stream.shutdown().await
    }

    async fn abort(&mut self) -> io::Result<()> {
        // ipstack has no explicit abort; dropping the stream causes the
        // stack to clean up its side. A true RST arrives with the
        // in-house stack.
        Ok(())
    }
}

/// UDP session adapter: our `UdpTransport` implemented over ipstack's
/// async datagram stream.
struct UdpIo {
    stream: IpStackUdpStream,
    nat: Arc<UdpNat>,
    source: SocketAddr,
}

#[async_trait]
impl UdpTransport for UdpIo {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let n = self.stream.read(buf).await?;
            // ipstack's UDP stream represents one flow; the remote is
            // the flow's peer. The table still gets a say, so a path
            // that expired or was never opened drops here too: the
            // datagram returns to the host only if the NAT allows it.
            let remote = self.stream.peer_addr();
            if self
                .nat
                .on_inbound(self.source, remote, std::time::Instant::now())
                .is_some()
            {
                return Ok((n, remote));
            }
        }
    }

    async fn send(&mut self, data: &[u8], _to: &SocketAddr) -> io::Result<()> {
        // ipstack routes by its own flow table; the destination address is
        // already determined by the session.
        self.stream.write_all(data).await
    }
}
