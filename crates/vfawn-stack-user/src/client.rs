// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Active-open engine: the other half of the in-house stack.
//!
//! [`NativeBackend`](crate::NativeBackend) terminates flows the network
//! started. This module starts them: a host asks for a TCP connection
//! to a remote address, the engine emits the SYN from the tunnel
//! address, and the same [`TcpSlot`] that serves inbound flows carries
//! the handshake, retransmissions and congestion control. UDP needs no
//! state machine — the engine frames datagrams and demultiplexes by
//! local port.
//!
//! The engine is deliberately small: one thread reads the device, one
//! thread runs the slots, and the host talks to the latter through a
//! command channel. It owns no runtime; the async surface
//! ([`TcpStream`], [`UdpSocket`]) only uses `tokio::sync` primitives,
//! so a caller may drive it from any runtime (or none, for the sync
//! parts).

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use bytes::BytesMut;
use tokio::sync::{mpsc as async_mpsc, oneshot};

use vfawn_core::{FlowInfo, Network, PacketDevice};
use vfawn_wire::flow::{FlowKey, flow_key};
use vfawn_wire::protocol::IpProtocol;

use crate::congestion::Cubic;
use crate::native_backend::{HostEvent, SessionHandoff, TcpSlot, WriteLane};
use crate::shards::{BufferPool, ShardBell};

/// How many packets one device read may return and the engine keeps in
/// flight: a burst larger than this waits in the device.
const READ_BATCH: usize = 32;
/// The engine's tick: retransmission and keepalive clocks have
/// millisecond resolution, and a 5 ms sleep costs nothing next to the
/// syscall the writer makes anyway.
const TICK: Duration = Duration::from_millis(5);
/// How long a host waits for a handshake before the connection is
/// written off. The slot's own SYN retries (five, backing off to two
/// seconds) usually finish first; this is the outer bound.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How much host output one flow may hold, matching the inbound lane.
const LANE_CAP: usize = 256 * 1024;
/// The ephemeral range the engine allocates local ports from.
const PORT_BASE: u16 = 32768;
const PORT_LAST: u16 = 60999;

/// What a [`ClientStack`] needs to know about its tunnel address.
#[derive(Clone, Copy, Debug)]
pub struct ClientConfig {
    /// The address the stack owns inside the tunnel. Outbound SYNs use
    /// it as their source; replies are matched against it.
    pub local_ip: IpAddr,
    /// The MSS advertised on the SYN. The tunnel MTU minus the IP and
    /// TCP headers is the right value; the default is a safe 1360.
    pub mss: u16,
    /// The device MTU, passed to the slots for frame sizing.
    pub mtu: usize,
}

impl ClientConfig {
    /// A config for `local_ip` with the default MSS and MTU.
    pub fn new(local_ip: IpAddr) -> Self {
        Self {
            local_ip,
            mss: 1360,
            mtu: 1500,
        }
    }
}

/// A running active-open stack. Dropping it stops the threads.
pub struct ClientStack {
    local_ip: IpAddr,
    mss: u16,
    commands: mpsc::Sender<Command>,
    next_port: AtomicU16,
    engine: Mutex<Option<JoinHandle<()>>>,
    reader: Mutex<Option<JoinHandle<()>>>,
    closed: Arc<AtomicBool>,
}

impl ClientStack {
    /// Start the engine over `device`. The device is duplicated: one
    /// handle reads, the other writes.
    pub fn start(device: Box<dyn PacketDevice>, config: ClientConfig) -> io::Result<Arc<Self>> {
        let mut reader_device = device.duplicate()?;
        let (commands_tx, commands_rx) = mpsc::channel();
        let (packets_tx, packets_rx) = mpsc::sync_channel(READ_BATCH);
        let (handoffs_tx, handoffs_rx) = mpsc::sync_channel(64);
        let wake = Arc::new(ShardBell::new());
        let pool = Arc::new(BufferPool::new());
        let closed = Arc::new(AtomicBool::new(false));
        let closed_for_reader = closed.clone();

        let mut engine = Engine {
            mss: config.mss,
            mtu: config.mtu,
            conns: HashMap::new(),
            pending: HashMap::new(),
            udp: HashMap::new(),
            sessions: handoffs_rx,
            sessions_tx: handoffs_tx,
            commands: commands_rx,
            packets: packets_rx,
            write: device,
            wake,
            pool,
            out: VecDeque::new(),
            stop: false,
        };

        let engine_thread = std::thread::Builder::new()
            .name("vfawn-client".into())
            .spawn(move || engine.run())?;
        let reader_thread = std::thread::Builder::new()
            .name("vfawn-client-read".into())
            .spawn(move || read_loop(&mut reader_device, &packets_tx, &closed_for_reader))?;

        Ok(Arc::new(Self {
            local_ip: config.local_ip,
            mss: config.mss,
            commands: commands_tx,
            next_port: AtomicU16::new(PORT_BASE),
            engine: Mutex::new(Some(engine_thread)),
            reader: Mutex::new(Some(reader_thread)),
            closed,
        }))
    }

    /// The tunnel address the stack sends from.
    pub fn local_ip(&self) -> IpAddr {
        self.local_ip
    }

    /// Open a TCP connection. The local port is chosen by the stack.
    pub async fn connect(&self, remote: SocketAddr) -> io::Result<TcpStream> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(stopped());
        }
        let local = SocketAddr::new(self.local_ip, self.allocate_port());
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Connect {
                local,
                remote,
                reply,
            })
            .map_err(|_| stopped())?;
        match tokio::time::timeout(CONNECT_TIMEOUT, answer).await {
            Ok(Ok(Ok(handoff))) => Ok(TcpStream::new(handoff, remote)),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err(stopped()),
            Err(_) => {
                let _ = self.commands.send(Command::Abort { local, remote });
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "wireguard client handshake timed out",
                ))
            }
        }
    }

    /// Bind a UDP endpoint inside the tunnel.
    pub async fn bind_udp(&self) -> io::Result<UdpSocket> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(stopped());
        }
        let local = SocketAddr::new(self.local_ip, self.allocate_port());
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::UdpBind { local, reply })
            .map_err(|_| stopped())?;
        let (local, datagrams) = answer.await.map_err(|_| stopped())??;
        Ok(UdpSocket {
            local,
            datagrams,
            commands: self.commands.clone(),
        })
    }

    /// Stop the engine and join its threads. Idempotent.
    pub fn shutdown(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.commands.send(Command::Stop);
        if let Ok(mut guard) = self.engine.lock()
            && let Some(thread) = guard.take()
        {
            let _ = thread.join();
        }
        if let Ok(mut guard) = self.reader.lock()
            && let Some(thread) = guard.take()
        {
            let _ = thread.join();
        }
    }

    fn allocate_port(&self) -> u16 {
        let mut port = self.next_port.fetch_add(1, Ordering::Relaxed);
        if !(PORT_BASE..=PORT_LAST).contains(&port) {
            self.next_port.store(PORT_BASE, Ordering::Relaxed);
            port = PORT_BASE;
        }
        port
    }

    /// The MSS the stack advertises.
    pub fn mss(&self) -> u16 {
        self.mss
    }
}

impl Drop for ClientStack {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn stopped() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "wireguard client stack stopped",
    )
}

fn read_loop(
    device: &mut Box<dyn PacketDevice>,
    packets: &mpsc::SyncSender<Vec<u8>>,
    closed: &AtomicBool,
) {
    let mut batch: Vec<BytesMut> = (0..READ_BATCH)
        .map(|_| BytesMut::with_capacity(64 * 1024))
        .collect();
    loop {
        match device.read_batch(&mut batch) {
            // A device with nothing to read may return zero (a mock or
            // a non-blocking tun); only the stop flag ends the loop.
            Ok(0) => {
                if closed.load(Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(count) => {
                for buffer in batch.iter_mut().take(count) {
                    if buffer.is_empty() {
                        continue;
                    }
                    if packets.send(buffer.split().to_vec()).is_err() {
                        return;
                    }
                }
            }
            Err(_) => break,
        }
    }
}

/// The engine's answer to [`Command::UdpBind`]: the bound address and
/// the stream of inbound datagrams.
type UdpBindReply = (
    SocketAddr,
    async_mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
);

/// A command from the host to the engine.
enum Command {
    Connect {
        local: SocketAddr,
        remote: SocketAddr,
        reply: oneshot::Sender<io::Result<SessionHandoff>>,
    },
    Abort {
        local: SocketAddr,
        remote: SocketAddr,
    },
    UdpBind {
        local: SocketAddr,
        reply: oneshot::Sender<io::Result<UdpBindReply>>,
    },
    UdpSend {
        local: SocketAddr,
        remote: SocketAddr,
        data: Vec<u8>,
    },
    UdpClose {
        local: SocketAddr,
    },
    Stop,
}

struct Conn {
    slot: TcpSlot,
}

struct Engine {
    mss: u16,
    mtu: usize,
    conns: HashMap<FlowKey, Conn>,
    pending: HashMap<FlowKey, oneshot::Sender<io::Result<SessionHandoff>>>,
    udp: HashMap<u16, async_mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>>,
    sessions: mpsc::Receiver<SessionHandoff>,
    sessions_tx: mpsc::SyncSender<SessionHandoff>,
    commands: mpsc::Receiver<Command>,
    packets: mpsc::Receiver<Vec<u8>>,
    write: Box<dyn PacketDevice>,
    wake: Arc<ShardBell>,
    pool: Arc<BufferPool>,
    out: VecDeque<BytesMut>,
    stop: bool,
}

impl Engine {
    fn run(&mut self) {
        while !self.stop {
            while let Ok(packet) = self.packets.try_recv() {
                self.on_packet(&packet);
            }
            while let Ok(command) = self.commands.try_recv() {
                self.on_command(command);
            }
            self.drain_handoffs();
            self.tick();
            self.flush();
            match self.commands.recv_timeout(TICK) {
                Ok(command) => self.on_command(command),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => self.stop = true,
            }
        }
        let _ = self.write.shutdown();
        for (_, conn) in self.conns.drain() {
            drop(conn);
        }
        self.flush();
    }

    fn on_command(&mut self, command: Command) {
        match command {
            Command::Connect {
                local,
                remote,
                reply,
            } => {
                let key = key_of(local, remote);
                if self.conns.contains_key(&key) || self.udp.contains_key(&local.port()) {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "local port already in use",
                    )));
                    return;
                }
                if local.is_ipv4() != remote.is_ipv4() {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "address families differ",
                    )));
                    return;
                }
                let flow = FlowInfo {
                    network: Network::Tcp,
                    source: local,
                    destination: remote,
                };
                let mut slot = TcpSlot::connect(
                    key,
                    flow,
                    local,
                    remote,
                    initial_sequence(),
                    self.mss,
                    self.sessions_tx.clone(),
                    self.wake.clone(),
                    Box::new(Cubic::new(self.mss)),
                    self.pool.clone(),
                );
                slot.begin(&mut self.out);
                self.pending.insert(key, reply);
                self.conns.insert(key, Conn { slot });
            }
            Command::Abort { local, remote } => {
                let key = key_of(local, remote);
                if let Some(mut conn) = self.conns.remove(&key) {
                    conn.slot.reset(&mut self.out);
                }
                if let Some(reply) = self.pending.remove(&key) {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection aborted",
                    )));
                }
            }
            Command::UdpBind { local, reply } => {
                if self.udp.contains_key(&local.port()) {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "local port already in use",
                    )));
                    return;
                }
                let (datagrams_tx, datagrams_rx) = async_mpsc::unbounded_channel();
                self.udp.insert(local.port(), datagrams_tx);
                let _ = reply.send(Ok((local, datagrams_rx)));
            }
            Command::UdpSend {
                local,
                remote,
                data,
            } => {
                if let Some(frame) = udp_frame(local, remote, &data) {
                    self.out.push_back(BytesMut::from(&frame[..]));
                }
            }
            Command::UdpClose { local } => {
                self.udp.remove(&local.port());
            }
            Command::Stop => self.stop = true,
        }
    }

    fn drain_handoffs(&mut self) {
        while let Ok(handoff) = self.sessions.try_recv() {
            let key = key_of(handoff.flow.source, handoff.flow.destination);
            if let Some(reply) = self.pending.remove(&key) {
                let _ = reply.send(Ok(handoff));
            }
        }
    }

    fn on_packet(&mut self, packet: &[u8]) {
        let Some(key) = flow_key(packet) else {
            return;
        };
        let key = if self.conns.contains_key(&key) {
            key
        } else {
            reverse(key)
        };
        if let Some(conn) = self.conns.get_mut(&key) {
            conn.slot.drive(packet, &mut self.out, &self.pool, self.mtu);
            return;
        }
        if key.protocol == IpProtocol::Udp {
            self.on_datagram(packet);
        }
    }

    fn on_datagram(&mut self, packet: &[u8]) {
        let Some((source, destination, data)) = udp_datagram(packet) else {
            return;
        };
        if let Some(sender) = self.udp.get(&destination.port()) {
            // `recv_from` 必须给出远端来源；返回 destination 会让多目标关联
            // 把回包当成来自隧道本地端点，无法按目标回写。
            let _ = sender.send((data.to_vec(), source));
        }
    }

    fn tick(&mut self) {
        for conn in self.conns.values_mut() {
            if let Some(due) = conn.slot.next_deadline()
                && due.is_zero()
            {
                conn.slot.fire(&mut self.out, &self.pool);
            }
            conn.slot.idle(&mut self.out);
        }
        let finished: Vec<FlowKey> = self
            .conns
            .iter()
            .filter(|(_, conn)| conn.slot.is_finished())
            .map(|(key, _)| *key)
            .collect();
        for key in finished {
            self.conns.remove(&key);
            if let Some(reply) = self.pending.remove(&key) {
                let _ = reply.send(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "connection closed before the handshake completed",
                )));
            }
        }
    }

    fn flush(&mut self) {
        if self.out.is_empty() {
            return;
        }
        let mut frames: Vec<BytesMut> = self.out.drain(..).collect();
        let mut written = 0;
        while written < frames.len() {
            match self.write.write_batch(&mut frames[written..]) {
                Ok(0) => break,
                Ok(count) => written += count,
                Err(_) => {
                    written = frames.len();
                }
            }
        }
        for frame in frames.into_iter().skip(written) {
            self.out.push_back(frame);
        }
    }
}

fn key_of(local: SocketAddr, remote: SocketAddr) -> FlowKey {
    FlowKey {
        src: local.ip(),
        src_port: local.port(),
        dst: remote.ip(),
        dst_port: remote.port(),
        protocol: IpProtocol::Tcp,
    }
}

fn reverse(key: FlowKey) -> FlowKey {
    FlowKey {
        src: key.dst,
        src_port: key.dst_port,
        dst: key.src,
        dst_port: key.src_port,
        protocol: key.protocol,
    }
}

/// A fresh initial sequence number. `RandomState` seeds its keys from
/// the OS once per process and re-keys per instance; hashing a counter
/// through it is unpredictable without pulling a random crate into the
/// stack, and the counter keeps two opens in the same instant apart.
fn initial_sequence() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.finish() as u32
}

fn udp_frame(local: SocketAddr, remote: SocketAddr, data: &[u8]) -> Option<Vec<u8>> {
    match (local.ip(), remote.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            crate::udp_slot::emit_udp_frame(source, destination, local.port(), remote.port(), data)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => vfawn_wire::emit::emit_udp_frame_v6(
            source,
            destination,
            local.port(),
            remote.port(),
            data,
        ),
        _ => None,
    }
}

fn udp_datagram(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, &[u8])> {
    match packet.first()? >> 4 {
        4 => {
            let ihl = usize::from(packet.first()? & 0x0f) * 4;
            if ihl < 20 || *packet.get(9)? != 17 {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
            let source = Ipv4Addr::new(
                *packet.get(12)?,
                *packet.get(13)?,
                *packet.get(14)?,
                *packet.get(15)?,
            );
            let destination = Ipv4Addr::new(
                *packet.get(16)?,
                *packet.get(17)?,
                *packet.get(18)?,
                *packet.get(19)?,
            );
            let udp = packet.get(ihl..total.min(packet.len()))?;
            let (source_port, destination_port, data) = udp_fields(udp)?;
            Some((
                SocketAddr::new(IpAddr::V4(source), source_port),
                SocketAddr::new(IpAddr::V4(destination), destination_port),
                data,
            ))
        }
        6 => {
            if *packet.get(6)? != 17 || packet.len() < 40 {
                return None;
            }
            let payload = usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
            let destination = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
            let udp = packet.get(40..40 + payload.min(packet.len() - 40))?;
            let (source_port, destination_port, data) = udp_fields(udp)?;
            Some((
                SocketAddr::new(IpAddr::V6(source), source_port),
                SocketAddr::new(IpAddr::V6(destination), destination_port),
                data,
            ))
        }
        _ => None,
    }
}

fn udp_fields(udp: &[u8]) -> Option<(u16, u16, &[u8])> {
    let source_port = u16::from_be_bytes([*udp.first()?, *udp.get(1)?]);
    let destination_port = u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]);
    let length = usize::from(u16::from_be_bytes([*udp.get(4)?, *udp.get(5)?]));
    let data = udp.get(8..length.min(udp.len()))?;
    Some((source_port, destination_port, data))
}

/// A TCP connection owned by the stack. Reads pull the slot's host
/// events, writes go into its lane.
pub struct TcpStream {
    events: async_mpsc::UnboundedReceiver<HostEvent>,
    lane: Arc<Mutex<WriteLane>>,
    wake: Arc<ShardBell>,
    remote: SocketAddr,
    pending: Vec<u8>,
    offset: usize,
    closed: bool,
}

impl TcpStream {
    fn new(handoff: SessionHandoff, remote: SocketAddr) -> Self {
        Self {
            events: handoff.events,
            lane: handoff.write_lane,
            wake: handoff.shard_wake,
            remote,
            pending: Vec::new(),
            offset: 0,
            closed: false,
        }
    }

    /// The remote endpoint this stream talks to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Read bytes from the connection; zero means the peer closed it.
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.pending.len() {
            return Ok(self.copy_out(buf));
        }
        loop {
            match self.events.recv().await {
                Some(HostEvent::Established) => continue,
                Some(HostEvent::Bytes(bytes)) => {
                    self.pending = bytes;
                    self.offset = 0;
                    return Ok(self.copy_out(buf));
                }
                Some(HostEvent::Closed) | None => return Ok(0),
            }
        }
    }

    fn copy_out(&mut self, buf: &mut [u8]) -> usize {
        let available = self.pending.len() - self.offset;
        let count = available.min(buf.len());
        let end = self.offset + count;
        if let (Some(source), Some(destination)) =
            (self.pending.get(self.offset..end), buf.get_mut(..count))
        {
            destination.copy_from_slice(source);
        }
        self.offset = end;
        count
    }

    /// Queue bytes for the peer, waiting while the lane is full.
    pub async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
        }
        let mut queued = data.len();
        while queued > 0 {
            let room = {
                let lane = self
                    .lane
                    .lock()
                    .map_err(|_| io::Error::other("write lane poisoned"))?;
                LANE_CAP.saturating_sub(lane.bytes)
            };
            if room == 0 {
                tokio::time::sleep(TICK).await;
                continue;
            }
            let chunk = queued.min(room);
            let take = data
                .get(data.len() - queued..data.len() - queued + chunk)
                .ok_or_else(|| io::Error::other("write chunk out of range"))?;
            {
                let mut lane = self
                    .lane
                    .lock()
                    .map_err(|_| io::Error::other("write lane poisoned"))?;
                lane.writes.push_back(take.to_vec());
                lane.bytes = lane.bytes.saturating_add(take.len());
            }
            self.wake.knock();
            queued -= chunk;
        }
        Ok(data.len())
    }

    /// Half-close: the slot turns the empty write into a FIN.
    pub fn shutdown(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Ok(mut lane) = self.lane.lock() {
            lane.writes.push_back(Vec::new());
            lane.bytes = lane.bytes.saturating_add(1);
        }
        self.wake.knock();
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A UDP endpoint inside the tunnel. One local port, many peers.
pub struct UdpSocket {
    local: SocketAddr,
    datagrams: async_mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    commands: mpsc::Sender<Command>,
}

impl UdpSocket {
    /// The tunnel-side address of this endpoint.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Send one datagram to `remote`.
    pub fn send_to(&self, data: &[u8], remote: SocketAddr) -> io::Result<usize> {
        if self.local.is_ipv4() != remote.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "address families differ",
            ));
        }
        self.commands
            .send(Command::UdpSend {
                local: self.local,
                remote,
                data: data.to_vec(),
            })
            .map_err(|_| stopped())?;
        Ok(data.len())
    }

    /// Receive one datagram and its source.
    pub async fn recv_from(&mut self) -> io::Result<(Vec<u8>, SocketAddr)> {
        self.datagrams
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "udp endpoint closed"))
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::UdpClose { local: self.local });
    }
}
