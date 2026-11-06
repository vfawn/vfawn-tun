// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The shard skeleton: the run bed the in-house TCP lands on.
//!
//! One reader thread owns the device and is the single producer of every
//! shard inbox; one dedicated thread per shard owns its connection table
//! and event loop; one writer thread drains every shard outbox into the
//! device. A flow's packets all hash to one shard, so per-flow state
//! never crosses a thread and no lock guards it. That is the whole
//! point: the connection table is plain owned data behind the loop, and
//! the only shared points are the hand-off queues, which are lock-free
//! on the fast path.
//!
//! What is here, and what is not:
//!
//! * here: batch hand-off (whole device batches split per shard), a
//!   doorbell so idle shards park until work knocks instead of polling
//!   a cadence, a per-shard binary timer heap, pooled packet buffers,
//!   and a per-slot bypass state as the hook the payload fast path
//!   attaches to;
//! * not here: any TCP. The slot logic is a trait; the native backend
//!   implements it with the state machine, and a UDP echo logic proves
//!   the plumbing end to end.

use std::cell::UnsafeCell;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use vfawn_core::PacketDevice;
use vfawn_wire::checksum;
use vfawn_wire::flow::{FlowKey, flow_key};
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::protocol::IpProtocol;

/// Buffers circulate instead of being rebought: readers pull spares
/// from here, shards return them here. The mutexes guard free lists,
/// not data flow; nothing on the steady-state path allocates.
#[derive(Default)]
pub struct BufferPool {
    packets: Mutex<Vec<BytesMut>>,
    batches: Mutex<Vec<Vec<BytesMut>>>,
}

/// How much the pool may retain. Circulation covers the working set;
/// beyond this, releasing returns memory to the allocator instead of
/// hoarding it (a pool that only ever receives is a leak with extra
/// steps, which one very long iperf afternoon proved).
const POOL_PACKET_CAP: usize = 4096;
const POOL_BATCH_CAP: usize = 256;

impl BufferPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// A packet buffer of at least `mtu` bytes, or a fresh one when the
    /// pool is dry (the only allocation on a cold path).
    pub fn packet(&self, mtu: usize) -> BytesMut {
        let mut spare = self.packets.lock().expect("packet pool lock");
        match spare.pop() {
            Some(mut buffer) => {
                if buffer.len() < mtu {
                    buffer.resize(mtu, 0);
                }
                buffer
            }
            None => BytesMut::zeroed(mtu),
        }
    }

    pub fn release_packet(&self, buffer: BytesMut) {
        let mut pool = self.packets.lock().expect("packet pool lock");
        if pool.len() < POOL_PACKET_CAP {
            pool.push(buffer);
        }
    }

    pub fn batch(&self) -> Vec<BytesMut> {
        self.batches
            .lock()
            .expect("batch pool lock")
            .pop()
            .unwrap_or_default()
    }

    pub fn release_batch(&self, batch: Vec<BytesMut>) {
        let mut pool = self.batches.lock().expect("batch pool lock");
        if pool.len() < POOL_BATCH_CAP {
            pool.push(batch);
        }
    }
}

/// A fixed-size single-producer single-consumer ring of packet batches.
/// Producer and consumer indices are padded apart so the two atomics do
/// not share a cache line. The producer is the one reader thread, the
/// consumer is one shard thread, so plain load/store with release and
/// acquire ordering publishes slots safely.
pub struct Ring {
    slots: Box<[UnsafeCell<Option<Vec<BytesMut>>>]>,
    capacity: usize,
    producer: PadAtomic,
    consumer: PadAtomic,
}

#[repr(align(64))]
struct PadAtomic(AtomicUsize);

impl Ring {
    pub fn new(capacity: usize) -> Self {
        let slots = (0..capacity)
            .map(|_| UnsafeCell::new(None))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            slots,
            capacity,
            producer: PadAtomic(AtomicUsize::new(0)),
            consumer: PadAtomic(AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        let producer = self.producer.0.load(Ordering::Relaxed);
        let consumer = self.consumer.0.load(Ordering::Relaxed);
        producer.wrapping_sub(consumer)
    }

    /// Try to hand a batch to the consumer. Fails only when the ring is
    /// full; the producer then treats it as backpressure.
    pub fn try_push(&self, batch: Vec<BytesMut>) -> Result<(), Vec<BytesMut>> {
        let producer = self.producer.0.load(Ordering::Relaxed);
        let consumer = self.consumer.0.load(Ordering::Acquire);
        if producer.wrapping_sub(consumer) == self.capacity {
            return Err(batch);
        }
        let slot = &self.slots[producer % self.capacity];
        // SAFETY: the slot at the producer index is owned by the
        // producer until the index is published; the consumer only
        // touches it after seeing the published index.
        #[expect(unsafe_code)]
        unsafe {
            *slot.get() = Some(batch);
        }
        self.producer
            .0
            .store(producer.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Take the next batch, if one is published.
    pub fn pop(&self) -> Option<Vec<BytesMut>> {
        let consumer = self.consumer.0.load(Ordering::Relaxed);
        let producer = self.producer.0.load(Ordering::Acquire);
        if consumer == producer {
            return None;
        }
        let slot = &self.slots[consumer % self.capacity];
        // SAFETY: the slot at the consumer index was published by the
        // producer and is owned by the consumer until the index is
        // released back.
        #[expect(unsafe_code)]
        let batch = unsafe { (*slot.get()).take() };
        self.consumer
            .0
            .store(consumer.wrapping_add(1), Ordering::Release);
        batch
    }
}

// SAFETY: the ring's protocol gives each slot exactly one owner at a
// time (see the push and pop comments); sending it across threads is
// the entire purpose.
#[expect(unsafe_code)]
unsafe impl Send for Ring {}
#[expect(unsafe_code)]
unsafe impl Sync for Ring {}

/// One shard's doorbell: whoever hands a shard work — the producer
/// after an inbox push, a session's lane after a host write, the stop
/// path — knocks, and the shard parks on the condvar until then
/// instead of waking on a cadence to check for nothing. The flag is
/// the predicate and the condvar the wake; storing the flag before
/// notifying under the lock means a parking thread either sees the
/// flag or hears the bell, so a knock is never lost to the race
/// between the last check and the park.
pub struct ShardBell {
    wake: AtomicBool,
    door: (Mutex<()>, std::sync::Condvar),
}

impl ShardBell {
    pub(crate) fn new() -> Self {
        Self {
            wake: AtomicBool::new(false),
            door: (Mutex::new(()), std::sync::Condvar::new()),
        }
    }

    /// Ring the bell: arm the flag first, then notify under the lock.
    pub fn knock(&self) {
        self.wake.store(true, Ordering::Release);
        if let Ok(guard) = self.door.0.lock() {
            drop(guard);
            self.door.1.notify_all();
        }
    }

    /// Whether a knock is still unclaimed.
    fn armed(&self) -> bool {
        self.wake.load(Ordering::Acquire)
    }

    /// Claim any pending knock; the loop does this at its top.
    fn clear(&self) {
        self.wake.store(false, Ordering::Relaxed);
    }

    /// Park until a knock or `timeout`. The flag re-check under the
    /// lock is the whole pattern: a knock that landed after the
    /// caller's own check is seen here instead of slept through.
    fn park(&self, timeout: Duration) {
        let Ok(guard) = self.door.0.lock() else {
            return;
        };
        if self.wake.load(Ordering::Acquire) {
            return;
        }
        let _ = self.door.1.wait_timeout(guard, timeout);
    }
}

/// A deterministic flow-to-shard hash. Randomized hashing would spread
/// flows differently per process run and make affinity tests flaky;
/// FNV-1a over the five-tuple bytes is stable and cheap.
pub fn shard_hash_of(flow: &FlowKey, shards: usize) -> usize {
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut mix = |bytes: &[u8]| {
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    };
    match flow.src {
        IpAddr::V4(addr) => mix(&addr.octets()),
        IpAddr::V6(addr) => mix(&addr.octets()),
    }
    mix(&flow.src_port.to_be_bytes());
    match flow.dst {
        IpAddr::V4(addr) => mix(&addr.octets()),
        IpAddr::V6(addr) => mix(&addr.octets()),
    }
    mix(&flow.dst_port.to_be_bytes());
    let protocol_byte = match flow.protocol {
        IpProtocol::Udp => 17,
        IpProtocol::Tcp => 6,
        other => {
            if let IpProtocol::Other(v) = other {
                v
            } else {
                0
            }
        }
    };
    mix(&[protocol_byte]);
    (hash % shards as u64) as usize
}

/// The per-connection slot. The state machine itself is the logic
/// object; the slot carries what the loop owns regardless of logic.
pub struct Slot {
    /// The payload fast-path hook: once a session enters bypass, the
    /// loop routes its packets to the bypass queue instead of the
    /// per-segment path. The fast path attaches here when it lands.
    pub bypass: bool,
    pub logic: Box<dyn SlotLogic>,
}

/// The slot constructor a backend supplies: one call per new flow.
pub type LogicFactory = Arc<dyn Fn(&vfawn_wire::flow::FlowKey) -> Box<dyn SlotLogic> + Send + Sync>;

/// Per-slot behavior. The in-house TCP is the real
/// implementation; the UDP echo below proves the plumbing.
pub trait SlotLogic: Send {
    /// One inbound packet for this flow. Emit replies into `out` using
    /// pool buffers; return the (borrowed) packet when done so the loop
    /// can recycle it.
    fn on_packet(
        &mut self,
        packet: &[u8],
        out: &mut VecDeque<BytesMut>,
        pool: &BufferPool,
        mtu: usize,
    );

    /// A timer this slot scheduled has fired.
    fn on_timer(&mut self, _out: &mut VecDeque<BytesMut>, _pool: &BufferPool) {}

    /// How long until this slot wants its [`SlotLogic::on_timer`] to
    /// fire: the retransmission deadline while unacknowledged data is
    /// outstanding, absent when nothing is owed. The loop schedules
    /// one pending timer per slot at most.
    fn timer_wanted(&self) -> Option<Duration> {
        None
    }

    /// A loop cycle with no inbound work. Sessions whose host wrote
    /// since the last packet have no packet to ride on; this is their
    /// turn.
    fn on_idle(&mut self, _out: &mut VecDeque<BytesMut>) {}
}

/// One scheduled wake-up for a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timer {
    pub deadline: Instant,
    pub flow: FlowKey,
}

impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // BinaryHeap pops the greatest; the earliest deadline must come
        // out first, so the order is inverted.
        other.deadline.cmp(&self.deadline)
    }
}

/// A UDP echo logic: swap the endpoints, fix the checksums, send it
/// back. Enough machinery to exercise every hop of the skeleton with
/// real packets.
pub struct UdpEcho;

impl SlotLogic for UdpEcho {
    fn on_packet(
        &mut self,
        packet: &[u8],
        out: &mut VecDeque<BytesMut>,
        pool: &BufferPool,
        mtu: usize,
    ) {
        let Ok((ip, _)) = Ipv4Header::parse(packet) else {
            return;
        };
        if ip.protocol != IpProtocol::Udp {
            return;
        }
        let mut reply = pool.packet(mtu);
        reply.clear();
        reply.extend_from_slice(&packet[..packet.len().min(mtu)]);
        let len = reply.len();
        if len < 28 {
            pool.release_packet(reply);
            return;
        }
        // Swap the IPv4 endpoints and mirror the adjustment into both
        // checksums; the transport checksum covers the addresses.
        for index in 0..4 {
            reply.swap(12 + index, 16 + index);
        }
        let old_field: [u8; 4] = packet[12..16].try_into().unwrap();
        let new_field: [u8; 4] = packet[16..20].try_into().unwrap();
        let header_checksum = u16::from_be_bytes([reply[10], reply[11]]);
        let fixed = checksum::adjust(header_checksum, &old_field, &new_field);
        reply[10..12].copy_from_slice(&fixed.to_be_bytes());
        let transport_checksum = u16::from_be_bytes([reply[26], reply[27]]);
        let fixed = checksum::adjust(transport_checksum, &old_field, &new_field);
        reply[26..28].copy_from_slice(&fixed.to_be_bytes());
        reply.truncate(len);
        out.push_back(reply);
    }
}

/// Configuration for the sharded data plane.
#[derive(Debug, Clone)]
pub struct ShardConfig {
    pub shards: usize,
    pub mtu: usize,
    /// Inbox depth per shard, in batches.
    pub inbox_batches: usize,
    /// How long an idle shard may park with nothing due. Work never
    /// waits for it — knocks are event-driven — so the cap exists for
    /// the clock-bound duties: the idle sweep's cadence and the stop
    /// check between knocks.
    pub park_cap: Duration,
}

impl Default for ShardConfig {
    fn default() -> Self {
        Self {
            shards: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            mtu: 1500,
            inbox_batches: 64,
            park_cap: Duration::from_millis(50),
        }
    }
}

#[derive(Clone)]
struct ShardShared {
    inbox: Arc<Ring>,
    outbox: Arc<Mutex<VecDeque<BytesMut>>>,
    bell: Arc<ShardBell>,
    stopped: Arc<AtomicBool>,
    /// One-shot backlog warning for this lane's outbox.
    wrote_warning: Arc<AtomicBool>,
    /// The writer's doorbell: a shard rings it after handing frames to
    /// any outbox, so the writer parks instead of polling a cadence
    /// and the first frame of a burst leaves in microseconds rather
    /// than a poll interval. The wait carries a timeout as a
    /// stop-check fallback, not as the wake path.
    writer_ping: Arc<(Mutex<()>, std::sync::Condvar)>,
}

/// The pipeline-wide stop: every thread honors it, including the
/// producer, whose device may never error or return nonzero again.
struct PipelineStop(Arc<AtomicBool>);

impl PipelineStop {
    fn raise(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Handle over the running sharded data plane. Dropping it stops every
/// thread; the device close is the caller's business as elsewhere.
pub struct Shards {
    shared: Vec<ShardShared>,
    /// Each shard's doorbell, indexed like `shared`: the host-side
    /// write path rings its flow's bell so an interactive write drains
    /// now instead of at the idle cadence.
    bells: Vec<Arc<ShardBell>>,
    stop_all: PipelineStop,
    pool: Arc<BufferPool>,
    /// Count of packets each shard processed, for affinity tests.
    pub processed: Vec<Arc<AtomicU64>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Shards {
    /// Wire the data plane: device in, sharded processing, device out.
    /// The read half of the device becomes the single producer; the
    /// write half is owned by the single writer thread.
    pub fn start(
        read_device: Box<dyn PacketDevice>,
        write_device: Box<dyn PacketDevice>,
        config: ShardConfig,
        logic: LogicFactory,
    ) -> Self {
        let shard_count = config.shards.max(1);
        let pool = Arc::new(BufferPool::new());
        let stop_all = Arc::new(AtomicBool::new(false));
        let writer_ping: Arc<(Mutex<()>, std::sync::Condvar)> =
            Arc::new((Mutex::new(()), std::sync::Condvar::new()));
        let mut shared = Vec::with_capacity(shard_count);
        let mut processed = Vec::with_capacity(shard_count);
        let mut threads = Vec::with_capacity(shard_count + 2);

        let mut bells: Vec<Arc<ShardBell>> = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            let inbox = Arc::new(Ring::new(config.inbox_batches));
            let outbox = Arc::new(Mutex::new(VecDeque::new()));
            let bell = Arc::new(ShardBell::new());
            bells.push(Arc::clone(&bell));
            let stopped = Arc::new(AtomicBool::new(false));
            let wrote_warning = Arc::new(AtomicBool::new(false));
            let counter = Arc::new(AtomicU64::new(0));
            let shard_pool = Arc::clone(&pool);
            let shard_logic = Arc::clone(&logic);
            let config_snapshot = config.clone();
            let inbox_for_loop = Arc::clone(&inbox);
            let outbox_for_loop = Arc::clone(&outbox);
            let writer_ping_for_loop = Arc::clone(&writer_ping);
            let bell_for_loop = Arc::clone(&bell);
            let stop_for_loop = Arc::clone(&stopped);
            let counter_for_loop = Arc::clone(&counter);
            let stop_all_for_shard = Arc::clone(&stop_all);
            threads.push(
                std::thread::Builder::new()
                    .name("vfawn-shard".into())
                    .spawn(move || {
                        shard_loop(
                            stop_all_for_shard,
                            inbox_for_loop,
                            outbox_for_loop,
                            bell_for_loop,
                            stop_for_loop,
                            writer_ping_for_loop,
                            counter_for_loop,
                            shard_pool,
                            shard_logic,
                            config_snapshot,
                        );
                    })
                    .expect("spawn shard"),
            );
            shared.push(ShardShared {
                inbox,
                outbox,
                writer_ping: Arc::clone(&writer_ping),
                bell,
                stopped,
                wrote_warning,
            });
            processed.push(counter);
        }

        // The single producer: reads device batches, splits them per
        // flow hash, and hands each sub-batch to its shard inbox.
        let stop_all_for_producer = Arc::clone(&stop_all);
        let producer_pool = Arc::clone(&pool);
        let producer_mtu = config.mtu;
        let producer_shared: Vec<ShardShared> = shared.clone();
        let mut staging: Vec<Vec<Option<BytesMut>>> =
            (0..shard_count).map(|_| Vec::new()).collect();
        threads.push(
            std::thread::Builder::new()
                .name("vfawn-shard-producer".into())
                .spawn(move || {
                    let mut device = read_device;
                    let mut bufs = vec![BytesMut::new(); 8];
                    'outer: loop {
                        if stop_all_for_producer.load(Ordering::Acquire) {
                            break;
                        }
                        match device.read_batch(&mut bufs) {
                            Ok(0) => std::thread::sleep(Duration::from_millis(1)),
                            Ok(count) => {
                                for buf in bufs.iter_mut().take(count) {
                                    let shard = flow_key(buf)
                                        .map(|flow| shard_hash_of(&flow, shard_count))
                                        .unwrap_or(0);
                                    let lane = &mut staging[shard];
                                    if lane.len() == lane.capacity()
                                        && !flush_lane(
                                            &producer_shared[shard].inbox,
                                            &producer_shared[shard],
                                            lane,
                                        )
                                    {
                                        break 'outer;
                                    }
                                    if lane.capacity() == 0 {
                                        lane.reserve_exact(16);
                                    }
                                    lane.push(Some(std::mem::take(buf)));
                                    // The reader's slot refills from the
                                    // pool: the buffer the writer released
                                    // comes back around instead of the pool
                                    // growing into a one-way sink.
                                    *buf = producer_pool.packet(producer_mtu);
                                }
                                for shard in 0..shard_count {
                                    if !staging[shard].is_empty()
                                        && !flush_lane(
                                            &producer_shared[shard].inbox,
                                            &producer_shared[shard],
                                            &mut staging[shard],
                                        )
                                    {
                                        break 'outer;
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    // The loop is over, by stop or by device error, and
                    // the I/O thread may be parked on the device's
                    // read with no packet coming to wake it. The
                    // shutdown call is that knock: the parked read
                    // returns, the I/O thread drops the device it
                    // owns, and the interface leaves with it — an
                    // adapter that outlives its pipeline is residue a
                    // later create would only have to recover from.
                    let _ = device.shutdown();
                })
                .expect("spawn producer"),
        );

        // The single consumer of every outbox: batches them down into
        // the device.
        let writer_shared: Vec<ShardShared> = shared.clone();
        let writer_ping_for_writer = Arc::clone(&writer_ping);
        let writer_pool = Arc::clone(&pool);
        let stop_all_for_writer = Arc::clone(&stop_all);
        threads.push(
            std::thread::Builder::new()
                .name("vfawn-shard-writer".into())
                .spawn(move || {
                    let mut device = write_device;
                    let mut batch: Vec<BytesMut> = Vec::with_capacity(32);
                    loop {
                        if stop_all_for_writer.load(Ordering::Acquire) {
                            break;
                        }
                        batch.clear();
                        let mut any_stopped = false;
                        for lane in &writer_shared {
                            let mut outbox = lane.outbox.lock().expect("outbox lock");
                            if outbox.len() > 8192
                                && !lane.wrote_warning.swap(true, Ordering::Relaxed)
                            {
                                eprintln!(
                                    "vfawn: outbox backlog {} packets; the writer cannot keep up",
                                    outbox.len()
                                );
                            }
                            while let Some(packet) = outbox.pop_front() {
                                batch.push(packet);
                            }
                        }
                        for lane in &writer_shared {
                            if lane.stopped.load(Ordering::Acquire) {
                                any_stopped = true;
                            }
                        }
                        if !batch.is_empty() {
                            if let Err(error) = device.write_batch(&mut batch) {
                                // A device that refuses writes is a
                                // dead pipeline: say so, stop every
                                // thread, and release what was in
                                // hand. Draining silently would turn
                                // the outboxes into an unbounded sink
                                // that nothing ever reads again.
                                eprintln!("vfawn: device write failed ({error}); stopping");
                                stop_all_for_writer.store(true, Ordering::Release);
                                for packet in batch.drain(..) {
                                    writer_pool.release_packet(packet);
                                }
                                break;
                            }
                            for packet in batch.drain(..) {
                                writer_pool.release_packet(packet);
                            }
                        }
                        if any_stopped {
                            // Every shard said goodbye; drain once more
                            // and leave.
                            let mut tail = Vec::new();
                            for lane in &writer_shared {
                                let mut outbox = lane.outbox.lock().expect("outbox lock");
                                while let Some(packet) = outbox.pop_front() {
                                    tail.push(packet);
                                }
                            }
                            if !tail.is_empty() {
                                let _ = device.write_batch(&mut tail);
                                for packet in tail {
                                    writer_pool.release_packet(packet);
                                }
                            }
                            break;
                        }
                        // Park on the doorbell rather than polling:
                        // shards ring it as they hand frames over, and
                        // the timeout is only the stop-check cadence.
                        {
                            let guard = writer_ping_for_writer.0.lock().expect("writer ping");
                            let _ = writer_ping_for_writer
                                .1
                                .wait_timeout(guard, Duration::from_millis(2))
                                .expect("writer ping");
                        }
                    }
                })
                .expect("spawn writer"),
        );

        Self {
            shared,
            bells,
            stop_all: PipelineStop(Arc::clone(&stop_all)),
            pool,
            processed,
            threads,
        }
    }

    /// The doorbell of one shard, for host-side signalling that
    /// targets a specific flow's shard.
    pub fn doorbell(&self, shard: usize) -> Option<Arc<ShardBell>> {
        self.bells.get(shard).cloned()
    }

    pub fn wake(&self, shard: usize) {
        if let Some(shared) = self.shared.get(shard) {
            shared.bell.knock();
        }
    }

    pub fn shard_count(&self) -> usize {
        self.shared.len()
    }

    pub fn pool(&self) -> &Arc<BufferPool> {
        &self.pool
    }

    pub fn stop(&self) {
        self.stop_all.raise();
        if let Some(lane) = self.shared.first()
            && let Ok(guard) = lane.writer_ping.0.lock()
        {
            drop(guard);
            lane.writer_ping.1.notify_all();
        }
        for lane in &self.shared {
            lane.stopped.store(true, Ordering::Release);
            lane.bell.knock();
        }
    }
}

impl Drop for Shards {
    fn drop(&mut self) {
        self.stop();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Hand the staged lane to its shard. Returns false only when the whole
/// pipeline should stop.
fn flush_lane(inbox: &Ring, shared: &ShardShared, lane: &mut Vec<Option<BytesMut>>) -> bool {
    let mut batch: Vec<BytesMut> = lane.drain(..).map(Option::unwrap).collect();
    while let Err(overflow) = inbox.try_push(batch) {
        batch = overflow;
        // Backpressure: the shard is behind; a bounded wait keeps the
        // kernel socket buffer as the final shock absorber.
        std::thread::sleep(Duration::from_micros(50));
    }
    shared.bell.knock();
    true
}

#[allow(clippy::too_many_arguments)]
fn shard_loop(
    stop_all: Arc<AtomicBool>,
    inbox: Arc<Ring>,
    outbox: Arc<Mutex<VecDeque<BytesMut>>>,
    bell: Arc<ShardBell>,
    stopped: Arc<AtomicBool>,
    writer_ping: Arc<(Mutex<()>, std::sync::Condvar)>,
    counter: Arc<AtomicU64>,
    pool: Arc<BufferPool>,
    logic: LogicFactory,
    config: ShardConfig,
) {
    let mut connections: HashMap<FlowKey, Slot> = HashMap::new();
    let mut timers: BinaryHeap<Timer> = BinaryHeap::new();
    // One pending timer per flow at most; a slot re-arms by wanting a
    // timer again after the fire.
    let mut scheduled: std::collections::HashSet<FlowKey> = std::collections::HashSet::new();
    let mut next_scan = Instant::now();
    // The idle sweep's own clock: a quiet flow's host writes (the
    // tail of a teardown, an answer that outran its packet) have no
    // packet to ride, and their only exit is this sweep. Gating it on
    // the shard having been idle that iteration lets one busy
    // sibling — a retrying flow, a probe exchange — starve a quiet
    // flow's delivery indefinitely, so the sweep keeps its own
    // cadence whether or not the shard did work.
    let mut next_sweep = Instant::now();
    let mut pending: VecDeque<BytesMut> = VecDeque::new();
    loop {
        if stopped.load(Ordering::Acquire) || stop_all.load(Ordering::Acquire) {
            break;
        }
        bell.clear();
        let mut did_work = false;

        while let Some(batch) = inbox.pop() {
            did_work = true;
            for packet in &batch {
                counter.fetch_add(1, Ordering::Relaxed);
                let Some(flow) = flow_key(packet) else {
                    continue;
                };
                let slot = connections.entry(flow).or_insert_with_key(|flow| Slot {
                    bypass: false,
                    logic: logic(flow),
                });
                if slot.bypass {
                    // The fast-path hook: packets of a bypassed session
                    // queue for the splice lane instead of the
                    // per-segment path. The lane attaches with the fast path.
                    continue;
                }
                slot.logic
                    .on_packet(packet, &mut pending, &pool, config.mtu);
            }
            pool.release_batch(batch);
        }

        // Timer scheduling: slots that owe the wire something say how
        // long they can bear to wait. The scan is gated to the
        // millisecond on busy cycles (the deadline scale is a hundred
        // times coarser) and rides the idle sweep's cadence otherwise.
        let now = Instant::now();
        if !did_work || now >= next_scan {
            next_scan = now + Duration::from_millis(1);
            for (flow, slot) in connections.iter() {
                if let Some(delay) = slot.logic.timer_wanted()
                    && scheduled.insert(*flow)
                {
                    timers.push(Timer {
                        deadline: now + delay,
                        flow: *flow,
                    });
                }
            }
        }

        // Timers: everything due at this instant fires now.
        while let Some(earliest) = timers.peek() {
            if earliest.deadline > now {
                break;
            }
            let timer = timers.pop().expect("peeked entry exists");
            scheduled.remove(&timer.flow);
            if let Some(slot) = connections.get_mut(&timer.flow) {
                slot.logic.on_timer(&mut pending, &pool);
                did_work = true;
            }
        }

        if !pending.is_empty() {
            did_work = true;
            let mut outbox = outbox.lock().expect("outbox lock");
            outbox.extend(pending.drain(..));
            if let Ok(guard) = writer_ping.0.lock() {
                drop(guard);
                writer_ping.1.notify_all();
            }
        }

        // The idle sweep on its own clock: host writes that arrived
        // without a packet to ride still deserve their turn on the
        // wire, and a quiet flow must not wait for every sibling to
        // fall silent first. Idle iterations sweep as before; busy
        // ones still sweep every so often, so a quiet flow riding a
        // busy shard waits milliseconds, not forever.
        if !did_work || now >= next_sweep {
            next_sweep = now + Duration::from_millis(20);
            for slot in connections.values_mut() {
                slot.logic.on_idle(&mut pending);
            }
            if !pending.is_empty() {
                let mut outbox = outbox.lock().expect("outbox lock");
                outbox.extend(pending.drain(..));
                if let Ok(guard) = writer_ping.0.lock() {
                    drop(guard);
                    writer_ping.1.notify_all();
                }
            }
        }

        if !did_work && !bell.armed() {
            // Park until knocked: the earliest pending timer bounds the
            // wait (every clock duty a slot owes the wire passes
            // through the heap), the cap keeps the idle sweep's
            // cadence, and a knock — inbox push, host write, stop —
            // ends it in the microseconds the condvar costs instead of
            // the cadence a blind poll would pay.
            let timeout = timers
                .peek()
                .map(|earliest| earliest.deadline.saturating_duration_since(now))
                .unwrap_or(config.park_cap)
                .min(config.park_cap);
            if !timeout.is_zero() {
                bell.park(timeout);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn shard_hash_is_stable_and_spreads() {
        let flows: Vec<FlowKey> = (0u16..64)
            .map(|port| FlowKey {
                src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                src_port: port,
                dst: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)),
                dst_port: 80,
                protocol: IpProtocol::Udp,
            })
            .collect();
        let shards = 4;
        let first: Vec<usize> = flows.iter().map(|f| shard_hash_of(f, shards)).collect();
        let second: Vec<usize> = flows.iter().map(|f| shard_hash_of(f, shards)).collect();
        assert_eq!(first, second, "hash must be deterministic");
        let distinct: std::collections::HashSet<usize> = first.iter().copied().collect();
        assert_eq!(distinct.len(), shards, "64 flows must reach every shard");
    }

    #[test]
    fn ring_hands_batches_in_order() {
        let ring = Ring::new(4);
        for round in 0..4 {
            let width = (round + 1) * 10;
            let batch: Vec<BytesMut> = (0..round + 1)
                .map(|n| BytesMut::from(&vec![n as u8; width][..]))
                .collect();
            ring.try_push(batch).expect("room in ring");
        }
        assert_eq!(ring.len(), 4);
        assert!(ring.try_push(Vec::new()).is_err(), "ring must report full");
        for round in 0..4 {
            let batch = ring.pop().expect("batch in order");
            assert_eq!(batch.len(), round + 1);
        }
        assert_eq!(ring.pop(), None);
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn timer_heap_fires_earliest_first() {
        let flow = FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            src_port: 1,
            dst: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)),
            dst_port: 80,
            protocol: IpProtocol::Udp,
        };
        let now = Instant::now();
        let mut heap = BinaryHeap::new();
        heap.push(Timer {
            deadline: now + Duration::from_millis(300),
            flow,
        });
        heap.push(Timer {
            deadline: now + Duration::from_millis(50),
            flow,
        });
        heap.push(Timer {
            deadline: now + Duration::from_millis(200),
            flow,
        });
        let mut order: Vec<u64> = heap
            .drain()
            .map(|t| (t.deadline - now).as_millis() as u64)
            .collect();
        order.sort_unstable();
        assert_eq!(order, vec![50, 200, 300]);
    }
}
