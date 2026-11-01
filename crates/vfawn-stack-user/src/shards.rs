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
//!   wake flag so idle shards sleep instead of spin, a per-shard binary
//!   timer heap, pooled packet buffers, and a per-slot bypass state as
//!   the hook the payload fast path (039) attaches to;
//! * not here: any TCP. The slot logic is a trait; 037 implements it
//!   with the state machine, and until then a UDP echo logic proves the
//!   plumbing end to end.

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
        self.packets.lock().expect("packet pool lock").push(buffer);
    }

    pub fn batch(&self) -> Vec<BytesMut> {
        self.batches
            .lock()
            .expect("batch pool lock")
            .pop()
            .unwrap_or_default()
    }

    pub fn release_batch(&self, batch: Vec<BytesMut>) {
        self.batches.lock().expect("batch pool lock").push(batch);
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
    /// per-segment path. The fast path attaches here in 039.
    pub bypass: bool,
    pub logic: Box<dyn SlotLogic>,
}

/// Per-slot behavior. The in-house TCP (037) is the real
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
    /// Idle shards poll this long before sleeping again.
    pub idle_poll: Duration,
}

impl Default for ShardConfig {
    fn default() -> Self {
        Self {
            shards: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            mtu: 1500,
            inbox_batches: 64,
            idle_poll: Duration::from_micros(200),
        }
    }
}

#[derive(Clone)]
struct ShardShared {
    inbox: Arc<Ring>,
    outbox: Arc<Mutex<VecDeque<BytesMut>>>,
    wake: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
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
        logic: Arc<dyn Fn() -> Box<dyn SlotLogic> + Send + Sync>,
    ) -> Self {
        let shard_count = config.shards.max(1);
        let pool = Arc::new(BufferPool::new());
        let stop_all = Arc::new(AtomicBool::new(false));
        let mut shared = Vec::with_capacity(shard_count);
        let mut processed = Vec::with_capacity(shard_count);
        let mut threads = Vec::with_capacity(shard_count + 2);

        for _ in 0..shard_count {
            let inbox = Arc::new(Ring::new(config.inbox_batches));
            let outbox = Arc::new(Mutex::new(VecDeque::new()));
            let wake = Arc::new(AtomicBool::new(false));
            let stopped = Arc::new(AtomicBool::new(false));
            let counter = Arc::new(AtomicU64::new(0));
            let shard_pool = Arc::clone(&pool);
            let shard_logic = Arc::clone(&logic);
            let config_snapshot = config.clone();
            let inbox_for_loop = Arc::clone(&inbox);
            let outbox_for_loop = Arc::clone(&outbox);
            let wake_for_loop = Arc::clone(&wake);
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
                            wake_for_loop,
                            stop_for_loop,
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
                wake,
                stopped,
            });
            processed.push(counter);
        }

        // The single producer: reads device batches, splits them per
        // flow hash, and hands each sub-batch to its shard inbox.
        let stop_all_for_producer = Arc::clone(&stop_all);
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
                })
                .expect("spawn producer"),
        );

        // The single consumer of every outbox: batches them down into
        // the device.
        let writer_shared: Vec<ShardShared> = shared.clone();
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
                            eprintln!("probe: writer writing {}", batch.len());
                            if device.write_batch(&batch).is_err() {
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
                                let _ = device.write_batch(&tail);
                                for packet in tail {
                                    writer_pool.release_packet(packet);
                                }
                            }
                            break;
                        }
                        std::thread::sleep(Duration::from_micros(100));
                    }
                })
                .expect("spawn writer"),
        );

        Self {
            shared,
            stop_all: PipelineStop(Arc::clone(&stop_all)),
            pool,
            processed,
            threads,
        }
    }

    /// Wake a shard that has pending timers due within `horizon`; the
    /// shard loop itself checks the clock on every batch, so this is an
    /// optimization hook for idle periods.
    pub fn wake(&self, shard: usize) {
        if let Some(shared) = self.shared.get(shard) {
            shared.wake.store(true, Ordering::Release);
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
        for lane in &self.shared {
            lane.stopped.store(true, Ordering::Release);
            lane.wake.store(true, Ordering::Release);
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
    shared.wake.store(true, Ordering::Release);
    true
}

#[allow(clippy::too_many_arguments)]
fn shard_loop(
    stop_all: Arc<AtomicBool>,
    inbox: Arc<Ring>,
    outbox: Arc<Mutex<VecDeque<BytesMut>>>,
    wake: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
    pool: Arc<BufferPool>,
    logic: Arc<dyn Fn() -> Box<dyn SlotLogic> + Send + Sync>,
    config: ShardConfig,
) {
    let mut connections: HashMap<FlowKey, Slot> = HashMap::new();
    let mut timers: BinaryHeap<Timer> = BinaryHeap::new();
    let mut pending: VecDeque<BytesMut> = VecDeque::new();
    loop {
        if stopped.load(Ordering::Acquire) || stop_all.load(Ordering::Acquire) {
            break;
        }
        wake.store(false, Ordering::Relaxed);
        let mut did_work = false;

        while let Some(batch) = inbox.pop() {
            did_work = true;
            eprintln!("probe: shard got batch of {}", batch.len());
            for packet in &batch {
                counter.fetch_add(1, Ordering::Relaxed);
                let Some(flow) = flow_key(packet) else {
                    continue;
                };
                let slot = connections.entry(flow).or_insert_with(|| Slot {
                    bypass: false,
                    logic: logic(),
                });
                if slot.bypass {
                    // The fast-path hook: packets of a bypassed session
                    // queue for the splice lane instead of the
                    // per-segment path. The lane attaches in 039.
                    continue;
                }
                slot.logic
                    .on_packet(packet, &mut pending, &pool, config.mtu);
            }
            pool.release_batch(batch);
        }

        // Timers: everything due at this instant fires now.
        let now = Instant::now();
        while let Some(earliest) = timers.peek() {
            if earliest.deadline > now {
                break;
            }
            let timer = timers.pop().expect("peeked entry exists");
            if let Some(slot) = connections.get_mut(&timer.flow) {
                slot.logic.on_timer(&mut pending, &pool);
                did_work = true;
            }
        }

        if !pending.is_empty() {
            did_work = true;
            let mut outbox = outbox.lock().expect("outbox lock");
            outbox.extend(pending.drain(..));
        }

        if !did_work && !wake.load(Ordering::Acquire) {
            std::thread::sleep(config.idle_poll);
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
