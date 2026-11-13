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
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;

use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vfawn_core::{
    DnsHijack, FlowInfo, FlowTrackerHook, IcmpPacket, Network, PacketDevice, SessionHandler,
    StackBackend, StackHandle, TcpSession, TcpTransport, UdpNat, UdpSession, UdpSessionMode,
    UdpTransport, Verdict,
};

use crate::ipstack_bridge;
use crate::live_flows::{FlowHold, LiveFlows};
use crate::syn_gate::SynGate;

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
    /// The device's directed broadcast, dropped by the bridge with the
    /// other non-unicast destinations.
    pub broadcast: Option<std::net::Ipv4Addr>,
    /// The host's runtime, when the host has one to lend. Sessions then
    /// run beside the host's own tasks — the handler can share pools,
    /// timers and connections with the rest of the host without
    /// crossing runtimes — and the backend builds no runtime of its own.
    /// `None` keeps the backend self-contained on a private runtime.
    /// Must be multi-threaded: ipstack tears streams down through
    /// `block_in_place`, which the current-thread flavor rejects.
    pub runtime: Option<tokio::runtime::Handle>,
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
            broadcast: None,
            runtime: None,
        }
    }
}

impl StackBackend for IpstackBackend {
    fn spawn(
        self: Box<Self>,
        device: Box<dyn PacketDevice>,
        handler: Arc<dyn SessionHandler>,
    ) -> io::Result<StackHandle> {
        if let Some(runtime) = &self.runtime
            && runtime.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the host runtime must be multi-threaded: ipstack tears streams down with block_in_place",
            ));
        }
        // Tracked: a drain ends when the last session does, and on a
        // borrowed runtime nothing but the drain's aborts ends the tasks.
        let handle = StackHandle::tracked();
        let write_device = device.duplicate()?;
        let gate = Arc::new(SynGate::new(Arc::clone(&handler)));
        let bridge = ipstack_bridge::start(
            device,
            write_device,
            Some(Arc::clone(&self.dns)),
            self.broadcast,
            Some(Arc::clone(&gate)),
            handle.clone(),
        );

        let config = {
            let mut builder = IpStackConfig::default();
            builder.mtu = self.mss + 40;
            builder.udp_timeout(std::time::Duration::from_secs(self.udp_timeout_secs));
            builder
        };
        let serve = Serve {
            config,
            bridge,
            gate,
            handler,
            udp_nat: Arc::clone(&self.udp_nat),
            handle: handle.clone(),
        };
        match self.runtime {
            Some(runtime) => {
                // The accept loop ends on the stop flag; the host's
                // runtime outlives it and owns nothing else of ours.
                drop(runtime.spawn(serve.run()));
            }
            None => spawn_private_runtime(serve)?,
        }
        Ok(handle)
    }
}

/// Everything the accept loop owns.
struct Serve {
    config: IpStackConfig,
    bridge: ipstack_bridge::Bridge,
    gate: Arc<SynGate>,
    handler: Arc<dyn SessionHandler>,
    udp_nat: Arc<UdpNat>,
    handle: StackHandle,
}

impl Serve {
    /// Accept until stopped, one registered task per stream, then reset
    /// the live flows and close the device so the bridge threads and the
    /// interface go with it.
    async fn run(self) {
        let Serve {
            config,
            bridge,
            gate,
            handler,
            udp_nat,
            handle,
        } = self;
        // Idle NAT mappings must not wait for the next datagram to be
        // reclaimed; a one-second sweep keeps close reports flowing on
        // quiet tables.
        let sweep = tokio::spawn(sweep_loop(Arc::clone(&udp_nat), handle.clone()));
        let ipstack_bridge::Bridge {
            io,
            flows,
            teardown,
        } = bridge;
        // Raised once the accept loop ends: every session's pending read
        // or write answers it at once.
        let (stopping, stopped) = tokio::sync::watch::channel(false);
        let mut stack = IpStack::new(config, io);
        loop {
            // ipstack's accept has no stop side; waiting for it to
            // notice a closed device is what kept whole process runs
            // holding their fds. The watcher races it and cancels the
            // wait.
            tokio::select! {
                _ = stop_watcher(&handle) => break,
                accepted = stack.accept() => match accepted {
                    Ok(stream) => {
                        spawn_session(&handle, stream, &handler, &gate, &udp_nat, &flows, &stopped)
                    }
                    Err(_) => break,
                },
            }
        }
        sweep.abort();
        // sing-tun's gVisor stack detaches, aborts every endpoint it
        // still holds, then closes (stack_gvisor.go:131-135); a connected
        // endpoint's abort is a reset. ipstack has no abort, so the
        // bridge resets the flows it saw established, from the cursors
        // the wire last showed, and the writer closes the device after
        // them. First, before any session ends: a dropped stream takes
        // its flow out of the table, and its reset with it.
        teardown.finish();
        // Then the sessions: handlers see their transport fail and run
        // their own ends now. ipstack's streams would not end with the
        // stack itself; each runs on until its own timeout.
        let _ = stopping.send(true);
        drop(stack);
        // The sessions finish on this runtime: their handlers run their
        // own ends, and a handler busy elsewhere past the grace window is
        // ended by the drain's aborts, which need a runtime to land on. A private
        // runtime retired here instead dropped every session the moment
        // the accept loop ended, so a drain always found the set empty
        // and no handler got to finish.
        while handle.live_sessions() > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }
}

/// One task per stream: a flow that wedges in dispatch must cost itself,
/// not the accept loop and every flow behind it. Each task registers
/// with the handle so a drain can wait for it, or abort it.
fn spawn_session(
    handle: &StackHandle,
    stream: IpStackStream,
    handler: &Arc<dyn SessionHandler>,
    gate: &Arc<SynGate>,
    udp_nat: &Arc<UdpNat>,
    flows: &Arc<LiveFlows>,
    stopped: &Stopped,
) {
    let task: Arc<OnceLock<tokio::task::AbortHandle>> = Arc::default();
    let guard = handle.enter({
        let task = Arc::clone(&task);
        move || {
            if let Some(task) = task.get() {
                task.abort();
            }
        }
    });
    let handler = Arc::clone(handler);
    let gate = Arc::clone(gate);
    let udp_nat = Arc::clone(udp_nat);
    let flows = Arc::clone(flows);
    let stopped = stopped.clone();
    let join = tokio::spawn(async move {
        let _session = guard;
        dispatch(stream, &handler, &gate, &udp_nat, &flows, stopped).await;
    });
    let _ = task.set(join.abort_handle());
}

/// The self-contained mode: a private multi-thread runtime on its own
/// thread, with panic containment around the whole accept loop.
fn spawn_private_runtime(serve: Serve) -> io::Result<()> {
    std::thread::Builder::new()
        .name("ipstack-runtime".into())
        .spawn(move || {
            // A panic in the runtime (a misbehaving handler, a stack
            // bug) must not take the process down; the stop flag still
            // works from outside, so shutdown remains reachable.
            // The runtime moves into a slot so the teardown path can
            // hand it to a bystander thread even after a panic.
            let runtime_slot: Arc<Mutex<Option<tokio::runtime::Runtime>>> =
                Arc::new(Mutex::new(None));
            let slot_for_body = Arc::clone(&runtime_slot);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                // Multi-thread, not current-thread: ipstack stream
                // teardown calls `block_in_place` on drop, which the
                // current-thread flavor rejects outright. Worker
                // count follows the machine: sessions are tasks and
                // two workers left a many-core box mostly idle.
                let workers = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(2);
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(workers)
                    .enable_all()
                    .build()
                    .expect("ipstack runtime");
                // The runtime lives in the slot so the teardown path
                // can hand it to a bystander thread; the guard holds
                // it here for the duration of the block_on.
                let mut guard = slot_for_body.lock().unwrap();
                *guard = Some(rt);
                guard.as_ref().unwrap().block_on(serve.run());
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
            let retired = runtime_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(rt) = retired {
                std::thread::spawn(move || drop(rt));
            }
        })?;
    Ok(())
}

/// Expire idle NAT mappings once a second until stopped.
async fn sweep_loop(table: Arc<UdpNat>, handle: StackHandle) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    while !handle.is_stopped() {
        tick.tick().await;
        table.sweep(std::time::Instant::now());
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
async fn dispatch(
    stream: IpStackStream,
    handler: &Arc<dyn SessionHandler>,
    gate: &SynGate,
    udp_nat: &Arc<UdpNat>,
    flows: &Arc<LiveFlows>,
    stopped: Stopped,
) {
    match stream {
        IpStackStream::Tcp(tcp) => {
            let local = tcp.local_addr();
            let peer = tcp.peer_addr();
            // Goes with the stream: once the stream is dropped ipstack
            // sends nothing more for the flow, and no reset is owed.
            let hold = flows.hold(local, peer);
            // Rebound after the hold so every arm drops the stream first.
            let tcp = tcp;
            let flow = FlowInfo {
                network: Network::Tcp,
                source: local,
                destination: peer,
            };
            // The gate judged the SYN on the device side and refused
            // flows never reach ipstack; a flow it did not hold (a full
            // table) is judged here. A SYN carries no payload either way.
            let Some(verdict) = gate
                .take(flow.source, flow.destination)
                .or_else(|| judged(handler, &flow))
            else {
                return;
            };
            let action = vfawn_core::verdict::execute(verdict, &flow);
            match action {
                vfawn_core::VerdictAction::CreateSession { tracker, .. } => {
                    let transport = Box::new(TcpIo {
                        stream: tcp,
                        stopped,
                        _hold: hold,
                    });
                    let tracker = tracker.map(|t| t as Arc<dyn FlowTrackerHook>);
                    let session = TcpSession::new(flow, transport, tracker);
                    handler.on_tcp(session).await;
                }
                vfawn_core::VerdictAction::Drop | vfawn_core::VerdictAction::Reset => {
                    // Only a verdict the gate missed lands here; the
                    // handshake is ipstack's by now, so the flow closes
                    // politely. Dropping the stream where it stands made
                    // ipstack's teardown block its own accept loop,
                    // wedging every later flow with it; a shutdown
                    // drains through its state machine.
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
                        stopped,
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
/// The stack's stop, as each session's transport sees it.
type Stopped = tokio::sync::watch::Receiver<bool>;

/// Run one transport operation unless the stack stops first; a stopped
/// stack answers every pending and later operation with an abort.
async fn unless_stopped<T>(
    stopped: &mut Stopped,
    operation: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::select! {
        biased;
        _ = stopped.wait_for(|stopped| *stopped) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "the stack stopped",
        )),
        result = operation => result,
    }
}

struct TcpIo {
    // Dropped before the hold: the stream's drop waits for its task, so
    // the flow leaves the table only once ipstack is done with it.
    stream: IpStackTcpStream,
    stopped: Stopped,
    _hold: FlowHold,
}

#[async_trait]
impl TcpTransport for TcpIo {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unless_stopped(&mut self.stopped, self.stream.read(buf)).await
    }

    async fn read_owned(&mut self) -> io::Result<Vec<u8>> {
        let mut scratch = vec![0u8; 2048];
        let n = unless_stopped(&mut self.stopped, self.stream.read(&mut scratch)).await?;
        scratch.truncate(n);
        Ok(scratch)
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        unless_stopped(&mut self.stopped, self.stream.write(data)).await
    }

    async fn shutdown_write(&mut self) -> io::Result<()> {
        unless_stopped(&mut self.stopped, self.stream.shutdown()).await
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
    stopped: Stopped,
    nat: Arc<UdpNat>,
    source: SocketAddr,
}

#[async_trait]
impl UdpTransport for UdpIo {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let n = unless_stopped(&mut self.stopped, self.stream.read(buf)).await?;
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
        unless_stopped(&mut self.stopped, self.stream.write_all(data)).await
    }
}
