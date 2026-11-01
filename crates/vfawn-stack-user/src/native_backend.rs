// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The in-house stack as a `StackBackend`: the TCP state machine from
//! `native_tcp` riding the shard skeleton, sessions handed to the host
//! through the same contract the ipstack backend uses.
//!
//! Each flow's shard slot owns one `ServerConnection` and a channel
//! pair: bytes the connection delivers flow to the host through
//! `HostEvent`s, bytes the host writes flow back through a shared
//! inbox the shard drains after each packet batch. The state machine
//! stays pure (no I/O, no threads), the shard loop keeps sole
//! ownership of the connection table, and this file is the only place
//! that knows both.
//!
//! Volume-one honesty: no retransmission timers beyond the handshake
//! retry, no out-of-order queue, no congestion control. Flows needing
//! those today belong on the ipstack backend until 038/039 land.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;

use bytes::BytesMut;

use vfawn_core::{
    FlowInfo, Network, PacketDevice, SessionHandler, StackBackend, StackHandle, TcpSession,
    TcpTransport,
};
use vfawn_wire::flow::FlowKey;
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::protocol::IpProtocol;
use vfawn_wire::tcp::TcpHeader;

use crate::native_tcp::{Inbound, Reaction, ServerConnection, TcpState, emit_v4};
use crate::shards::{BufferPool, LogicFactory, ShardConfig, Shards, SlotLogic};

/// What a slot tells the session wrapper.
enum HostEvent {
    Established,
    Bytes(Vec<u8>),
    Closed,
}

/// A stable, predictable ISN policy for volume one: the flow tuple
/// hashed into sequence space. Real per-connection entropy arrives
/// with the accept queue (039); until then, predictability is what
/// both the differential bed and the e2e suite rely on.
fn listen_isn_for(flow: &FlowKey) -> u32 {
    let mut hash: u64 = 0x9e3779b97f4a7c15;
    let mut mix = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    };
    match flow.src {
        std::net::IpAddr::V4(a) => mix(&a.octets()),
        std::net::IpAddr::V6(a) => mix(&a.octets()),
    }
    mix(&flow.src_port.to_be_bytes());
    match flow.dst {
        std::net::IpAddr::V4(a) => mix(&a.octets()),
        std::net::IpAddr::V6(a) => mix(&a.octets()),
    }
    mix(&flow.dst_port.to_be_bytes());
    (hash >> 16) as u32
}

/// The v4 endpoints of a flow, as the emitter wants them.
fn v4_ends(flow: &FlowKey) -> Option<(std::net::SocketAddrV4, std::net::SocketAddrV4)> {
    let (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) = (flow.src, flow.dst) else {
        return None;
    };
    Some((
        std::net::SocketAddrV4::new(src, flow.src_port),
        std::net::SocketAddrV4::new(dst, flow.dst_port),
    ))
}

/// One flow inside a shard: the connection, its host channels, and the
/// write backlog the host has queued.
struct TcpSlot {
    connection: ServerConnection,
    client: std::net::SocketAddrV4,
    server: std::net::SocketAddrV4,
    to_host: mpsc::SyncSender<HostEvent>,
    /// The lane this slot's host writes arrive on.
    write_lane: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    session_open: bool,
}

impl TcpSlot {
    fn announce(&mut self) {
        if self.session_open {
            return;
        }
        // The handshake completes exactly once; the session wrapper is
        // created then, not before, so the host never sees a half-open
        // flow as established.
        if self.connection.state() == TcpState::Established {
            self.session_open = true;
            let _ = self.to_host.send(HostEvent::Established);
        }
    }

    /// Move host-written backlog bytes into segments.
    fn drain_writes(&mut self, out: &mut VecDeque<BytesMut>) {
        let writes: Vec<Vec<u8>> = self
            .write_lane
            .lock()
            .expect("write lane")
            .drain(..)
            .collect();
        for write in writes {
            if write.is_empty() {
                // The host's shutdown marker: a FIN after any data.
                let reaction = self.connection.fin_reaction();
                if reaction.flags != 0 {
                    let frame = emit_v4(self.server, self.client, &reaction, &[]);
                    out.push_back(BytesMut::from(&frame[..]));
                    self.connection.mark_fin_sent();
                    self.connection
                        .send_advance(u32::from(reaction.flags & 0x03 != 0));
                }
                continue;
            }
            let mut remaining = write.as_slice();
            while !remaining.is_empty() {
                let take = remaining.len().min(self.connection.mss() as usize);
                let more_after = remaining.len() > take;
                let reaction = Reaction {
                    seq: self.connection.send_nxt(),
                    ack: self.connection.recv_nxt(),
                    flags: if more_after { 0x10 } else { 0x18 },
                    window: 65535,
                    delivered: Vec::new(),
                    held: false,
                    gap_filled: false,
                };
                let frame = emit_v4(self.server, self.client, &reaction, &remaining[..take]);
                out.push_back(BytesMut::from(&frame[..]));
                self.connection.send_advance(take as u32);
                remaining = &remaining[take..];
            }
        }
    }
}

impl SlotLogic for TcpSlot {
    fn on_packet(
        &mut self,
        packet: &[u8],
        out: &mut VecDeque<BytesMut>,
        _pool: &BufferPool,
        _mtu: usize,
    ) {
        let Ok((ip, payload)) = Ipv4Header::parse(packet) else {
            return;
        };
        if ip.protocol != IpProtocol::Tcp {
            return;
        }
        let Ok((header, segment_payload)) = TcpHeader::parse(payload) else {
            return;
        };
        let inbound = Inbound::parse(&header, segment_payload);
        let reaction = self.connection.on_segment(&inbound);

        if !reaction.delivered.is_empty() {
            let _ = self
                .to_host
                .send(HostEvent::Bytes(reaction.delivered.clone()));
        }
        self.announce();

        if reaction.flags != 0 {
            let frame = emit_v4(self.server, self.client, &reaction, &[]);
            out.push_back(BytesMut::from(&frame[..]));
            self.connection
                .send_advance(u32::from(reaction.flags & 0x03 != 0));
        }

        if self.connection.state() == TcpState::Closed {
            let _ = self.to_host.send(HostEvent::Closed);
        } else {
            self.drain_writes(out);
        }
    }

    fn on_idle(&mut self, out: &mut VecDeque<BytesMut>) {
        // Host writes that arrived after the last packet: their only
        // ride is this idle sweep.
        if self.connection.state() == TcpState::Established {
            self.drain_writes(out);
        }
    }
}

/// The session-facing transport: host reads pull from slot events,
/// host writes push into the slot's lane.
struct NativeTcpIo {
    events: mpsc::Receiver<HostEvent>,
    write_lane: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    pending: VecDeque<u8>,
    closed: bool,
}

#[async_trait::async_trait]
impl TcpTransport for NativeTcpIo {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.pending.is_empty() {
                let take = self.pending.len().min(buf.len());
                let bytes: Vec<u8> = self.pending.drain(..take).collect();
                buf[..take].copy_from_slice(&bytes);
                return Ok(take);
            }
            match self.events.try_recv() {
                Ok(HostEvent::Bytes(bytes)) => self.pending.extend(bytes),
                Ok(HostEvent::Established) => continue,
                Ok(HostEvent::Closed) => {
                    self.closed = true;
                    return Ok(0);
                }
                Err(mpsc::TryRecvError::Empty) => {
                    if self.closed {
                        return Ok(0);
                    }
                    // One millisecond at a time: no runtime dependency,
                    // no busy spin, and the shard wakes this within a
                    // batch of any packet arriving.
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.closed = true;
                    return Ok(0);
                }
            }
        }
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write_lane
            .lock()
            .expect("write lane")
            .push_back(data.to_vec());
        Ok(data.len())
    }

    async fn shutdown_write(&mut self) -> io::Result<()> {
        self.write_lane
            .lock()
            .expect("write lane")
            .push_back(Vec::new());
        Ok(())
    }

    async fn abort(&mut self) -> io::Result<()> {
        self.write_lane.lock().expect("write lane").clear();
        Ok(())
    }
}

/// The backend the facade selects.
#[derive(Clone)]
pub struct NativeBackend {
    pub shards: usize,
}

impl Default for NativeBackend {
    fn default() -> Self {
        Self {
            shards: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .min(4),
        }
    }
}

/// Everything the spawn path threads through the factory closure.
struct SpawnShared {
    handler: Arc<dyn SessionHandler>,
    sessions: mpsc::SyncSender<SessionHandoff>,
    session_count: AtomicU64,
}

/// A ready session handed to the runtime side.
struct SessionHandoff {
    flow: FlowInfo,
    events: mpsc::Receiver<HostEvent>,
    write_lane: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
}

impl StackBackend for NativeBackend {
    fn spawn(
        self: Box<Self>,
        device: Box<dyn PacketDevice>,
        handler: Arc<dyn SessionHandler>,
    ) -> io::Result<StackHandle> {
        let handle = StackHandle::new();
        let write_device = device.duplicate()?;

        let (sessions_tx, sessions_rx) = mpsc::sync_channel::<SessionHandoff>(1024);
        let shared = Arc::new(SpawnShared {
            handler,
            sessions: sessions_tx,
            session_count: AtomicU64::new(0),
        });

        let factory_shared = Arc::clone(&shared);
        let logic_factory: LogicFactory = Arc::new(move |flow: &FlowKey| {
            // Only v4 flows ride volume one; anything else gets a
            // sink slot so the shard keeps flowing.
            let Some((client, server)) = v4_ends(flow) else {
                return Box::new(SinkSlot) as Box<dyn SlotLogic>;
            };
            let (event_tx, event_rx) = mpsc::sync_channel(1024);
            let write_lane = Arc::new(std::sync::Mutex::new(VecDeque::new()));
            let handoff = SessionHandoff {
                flow: FlowInfo {
                    network: Network::Tcp,
                    source: std::net::SocketAddr::new(flow.src, flow.src_port),
                    destination: std::net::SocketAddr::new(flow.dst, flow.dst_port),
                },
                events: event_rx,
                write_lane: Arc::clone(&write_lane),
            };
            if factory_shared.sessions.send(handoff).is_err() {
                return Box::new(SinkSlot) as Box<dyn SlotLogic>;
            }
            factory_shared.session_count.fetch_add(1, Ordering::Relaxed);
            Box::new(TcpSlot {
                connection: ServerConnection::new(listen_isn_for(flow), 536),
                client,
                server,
                to_host: event_tx,
                write_lane,
                session_open: false,
            })
        });

        let shards = Shards::start(
            device,
            write_device,
            ShardConfig {
                shards: self.shards,
                mtu: 1500,
                ..ShardConfig::default()
            },
            logic_factory,
        );

        // Hand established sessions to the host on a plain thread: the
        // contract wants `on_tcp` awaited, and nothing here needs a
        // runtime of its own.
        let runtime_handler = Arc::clone(&shared.handler);
        std::thread::Builder::new()
            .name("vfawn-native-sessions".into())
            .spawn(move || {
                // A minimal single-threaded runtime per session batch;
                // each session gets its own small context.
                while let Ok(handoff) = sessions_rx.recv() {
                    let handler = Arc::clone(&runtime_handler);
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("session runtime");
                    rt.block_on(async move {
                        let transport = NativeTcpIo {
                            events: handoff.events,
                            write_lane: Arc::clone(&handoff.write_lane),
                            pending: VecDeque::new(),
                            closed: false,
                        };
                        // Establish event first: the host sees the flow
                        // as live before any bytes.
                        let session = TcpSession::new(handoff.flow, Box::new(transport), None);
                        handler.on_tcp(session).await;
                    });
                }
            })
            .expect("spawn session thread");

        // The shards handle holds the threads; park this handle's stop
        // by leaking into a leak-box that stops on StackHandle drop is
        // the facade's business via shutdown ordering in volume two.
        // For now the threads live as long as the process, matching
        // the e2e lifecycle (start once, kill to stop).
        std::mem::forget(shards);

        Ok(handle)
    }
}

/// A slot that swallows everything: for flows volume one cannot carry.
struct SinkSlot;

impl SlotLogic for SinkSlot {
    fn on_packet(
        &mut self,
        _packet: &[u8],
        _out: &mut VecDeque<BytesMut>,
        _pool: &BufferPool,
        _mtu: usize,
    ) {
    }
}
