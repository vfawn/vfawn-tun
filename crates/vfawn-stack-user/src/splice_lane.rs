// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The payload fast path: once a relay flow is established, its data
//! segments skip the TCP state machine's session machinery entirely.
//! The dispatch parses just enough header to identify the flow and the
//! payload range, then the bytes move to the outbound socket with one
//! write syscall (the v0 lane; the kernel-pipe `splice(2)` variant
//! replaces the write once the PoC's numbers justify the pipe pair's
//! setup, and both shapes skip the session channel and the relay task).
//!
//! The state machine stays in charge of the connection's control
//! plane: handshake, window accounting, teardown. What bypass removes
//! is the payload's trip through the read channel, the producer, the
//! shard ring, the slot, the session channel, and the relay task's
//! wakeup. The ACK clock still runs — the dispatch stamps it from the
//! shared cursors below, and the machine adopts their position when a
//! slow-path segment next arrives, so the two views of the sequence
//! space converge by construction rather than by coordination.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use vfawn_wire::flow::FlowKey;
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::protocol::IpProtocol;
use vfawn_wire::tcp::{TcpFlags, TcpHeader};

/// A registered fast-path flow: the outbound socket the payload
/// writes to, plus the shared sequence view the two halves of the
/// path maintain together. The io thread's dispatch advances
/// `recv_nxt` atomically as it claims segments; the slot's state
/// machine reads it to catch up before judging any segment that
/// reached it the slow way, and refreshes `send_nxt`/`window` after
/// its own emissions so the dispatch's ACK stamps stay current.
///
/// The entry owns its descriptor: registration duplicates the relay's
/// fd, and the last reference closing releases it. That decouples the
/// lane's right to write from the relay handle's lifetime — a dispatch
/// holding an entry can never write into an fd number the kernel has
/// already recycled into an unrelated socket.
pub struct SpliceEntry {
    outbound_fd: RawFd,
    /// RCV.NXT as the dispatch advances it (Release on advance,
    /// Acquire on read; the slot adopts values it sees here).
    recv_nxt: AtomicU32,
    /// SND.NXT for ACK stamps; written by the slot only. A stale value
    /// merely lowers the dispatch's hit rate — the eligibility check
    /// fails and the segment rides the slot — never its correctness.
    send_nxt: AtomicU32,
    /// The 16-bit window field the dispatch stamps, matching what the
    /// machine's own reactions carry.
    window: AtomicU16,
    /// Whether the shared cursors hold the connection's truth. The
    /// relay's register knows only the fd; the slot, which owns the
    /// connection, activates the entry when it first sees the flow.
    active: AtomicBool,
}

impl SpliceEntry {
    fn new(fd: RawFd) -> Self {
        Self {
            outbound_fd: fd,
            recv_nxt: AtomicU32::new(0),
            send_nxt: AtomicU32::new(0),
            window: AtomicU16::new(0),
            active: AtomicBool::new(false),
        }
    }

    /// Seed the shared cursors from the machine's state. Called once,
    /// by the slot, on the first segment it sees for a registered
    /// flow; after this the io thread's dispatch claims the flow's
    /// steady segments before they enter the read channel.
    pub fn activate(&self, recv_nxt: u32, send_nxt: u32, window: u16) {
        self.recv_nxt.store(recv_nxt, Ordering::Release);
        self.send_nxt.store(send_nxt, Ordering::Release);
        self.window.store(window, Ordering::Release);
        self.active.store(true, Ordering::Release);
    }

    /// Whether the shared cursors are live.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Take the flow off the fast path. The slot does this when the
    /// outbound socket refuses writes: the non-blocking fd under
    /// backpressure would otherwise turn each refused payload into an
    /// acknowledged-but-undelivered byte, and the peer at the far end
    /// waits for data that never comes. After this, the dispatch
    /// declines the flow's segments and the session channel carries
    /// them, with the relay's async write to wait out the pressure.
    pub fn deactivate(&self) {
        self.active.store(false, Ordering::Release);
    }

    /// The current shared receive cursor.
    pub fn recv_nxt_value(&self) -> u32 {
        self.recv_nxt.load(Ordering::Acquire)
    }

    /// The outbound descriptor the payload writes to.
    pub fn outbound_fd(&self) -> RawFd {
        self.outbound_fd
    }

    /// Advance the shared receive cursor from the machine's known
    /// position. A failed compare means the dispatch already moved it
    /// — the machine's value is stale by less than this segment, which
    /// its next catch-up absorbs — so the failure is left alone.
    pub fn advance_recv(&self, expected: u32, new: u32) {
        let _ = self
            .recv_nxt
            .compare_exchange(expected, new, Ordering::AcqRel, Ordering::Relaxed);
    }

    /// Restamp the fields the dispatch reads: the send cursor and
    /// window move when the machine emits, and the dispatch's stamps
    /// should track them.
    pub fn refresh(&self, send_nxt: u32, window: u16) {
        self.send_nxt.store(send_nxt, Ordering::Release);
        self.window.store(window, Ordering::Release);
    }
}

impl Drop for SpliceEntry {
    fn drop(&mut self) {
        // SAFETY: the entry owns this descriptor outright (the
        // register-side dup); the last Arc reference is gone, so no
        // dispatch can hold it mid-write.
        #[expect(unsafe_code)]
        unsafe {
            libc::close(self.outbound_fd);
        }
    }
}

/// The lane's shared registry: flows opt in by registering their
/// outbound fd; the device's read loop and the shard's dispatch
/// consult this before running the full pipeline.
#[derive(Default)]
pub struct SpliceLane {
    /// Reader-heavy by far: the device's read loop and every shard
    /// consult it per packet, while only session setup and teardown
    /// write. The reader lock keeps those lookups off each other's
    /// way; the writer lock is the rare relay spawn/exit.
    targets: RwLock<HashMap<FlowKey, Arc<SpliceEntry>>>,
    /// The read loop's outbound staging: claimed payloads accumulate
    /// per socket through a read batch and leave as one write each at
    /// its end. Only the I/O thread touches this — the claim and its
    /// finish run on that thread — so the mutex is uncontended
    /// insurance, not synchronization.
    staged: Mutex<HashMap<RawFd, StagedOutbound>>,
}

impl SpliceLane {
    pub fn new() -> Self {
        Self::default()
    }

    /// The process-wide lane: the relay handler's side, the shard's
    /// side, and the device's read loop meet here without threading an
    /// Arc through the session contract. One process runs one stack;
    /// the singleton is the honest shape for that.
    pub fn global() -> &'static SpliceLane {
        static LANE: std::sync::OnceLock<SpliceLane> = std::sync::OnceLock::new();
        LANE.get_or_init(SpliceLane::new)
    }

    /// Register a flow for the fast path. The lane keeps its own
    /// descriptor — a dup of the relay's fd — so the entry's right to
    /// write survives the relay handle's lifetime; a registration that
    /// cannot dup does not ride the lane.
    pub fn register(&self, flow: FlowKey, fd: RawFd) {
        // SAFETY: fcntl(2) duplicating a live descriptor the caller
        // owns; the result is a fresh fd this entry exclusively owns.
        #[expect(unsafe_code)]
        let owned = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if owned < 0 {
            return;
        }
        self.targets
            .write()
            .expect("splice lane")
            .insert(flow, Arc::new(SpliceEntry::new(owned)));
    }

    /// Remove a flow (teardown or fallback). The entry's descriptor
    /// closes when the last in-flight dispatch lets go of it.
    pub fn unregister(&self, flow: &FlowKey) {
        self.targets.write().expect("splice lane").remove(flow);
    }

    /// The entry for a flow, if it rides the lane.
    pub fn entry_for(&self, flow: &FlowKey) -> Option<Arc<SpliceEntry>> {
        self.targets.read().expect("splice lane").get(flow).cloned()
    }

    /// The outbound fd for a flow, if it rides the lane.
    pub fn fd_for(&self, flow: &FlowKey) -> Option<RawFd> {
        self.entry_for(flow).map(|entry| entry.outbound_fd())
    }

    /// The io-loop dispatch: try to handle a packet entirely inside
    /// the device's read loop, before it enters the read channel. A
    /// claimed segment costs a header parse, an atomic compare, one
    /// outbound write, and one staged ACK — zero thread crossings,
    /// against the six the channel-producer-ring-shard chain crosses.
    ///
    /// The ACK lands in `produced`, which the device's I/O loop sends
    /// through its own write path at the end of the read batch: the
    /// dispatch never touches a queue or a thread it does not own —
    /// the write channel keeps its single producer, which the
    /// multi-pusher experiment measured into both a downlink collapse
    /// (2432 to 121 Mbit/s) and intermittent end-of-test stalls.
    ///
    /// False is a plain "not mine": unregistered flow, control
    /// segment, gap, or an outbound socket under backpressure — the
    /// packet then rides the normal path unchanged. The cursor moves
    /// only after the payload write succeeded, so the dispatch never
    /// acknowledges what it did not deliver.
    pub fn try_dispatch(&self, packet: &[u8], produced: &mut Vec<bytes::BytesMut>) -> bool {
        let Ok((ip, rest)) = Ipv4Header::parse(packet) else {
            return false;
        };
        if ip.protocol != IpProtocol::Tcp {
            return false;
        }
        let Ok((tcp, payload)) = TcpHeader::parse(rest) else {
            return false;
        };
        // The steady shape only: pure data (an ACK carrying payload,
        // no control flags). Everything else belongs to the machine.
        // The empty-payload test comes first and costs nothing beyond
        // the parses: the downlink's whole acknowledgment stream takes
        // this exit, and it must not pay for a key it will never use.
        let control = TcpFlags::SYN.union(TcpFlags::RST).union(TcpFlags::FIN);
        if payload.is_empty()
            || !tcp.flags.contains(TcpFlags::ACK)
            || (tcp.flags.bits() & control.bits()) != 0
        {
            return false;
        }
        let key = FlowKey {
            src: IpAddr::V4(ip.src),
            src_port: tcp.src_port,
            dst: IpAddr::V4(ip.dst),
            dst_port: tcp.dst_port,
            protocol: IpProtocol::Tcp,
        };
        let Some(entry) = self.entry_for(&key) else {
            return false;
        };
        if !entry.is_active() {
            return false;
        }
        // The same admission the slot's fast path makes, against the
        // shared cursor instead of the machine's field: in-order
        // (seq == RCV.NXT) and current (ack == SND.NXT, so the
        // machine owes this segment no acknowledgment processing).
        let expected = entry.recv_nxt.load(Ordering::Acquire);
        if tcp.seq != expected {
            return false;
        }
        let stamp_seq = entry.send_nxt.load(Ordering::Acquire);
        if tcp.ack != stamp_seq {
            return false;
        }
        // The payload joins this batch's outbound staging rather than
        // paying a write per segment: the read batch's end flushes one
        // write per socket, the same amortization the slow path's
        // accumulator measured. A full-enough staging (an outbound
        // socket under sustained pressure) declines further claims —
        // the slot's fold-back path is the honest exit for overflow.
        {
            let mut staged = self.staged.lock().expect("outbound staging");
            match staged.entry(entry.outbound_fd()) {
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    if slot.get_mut().buffer.len() >= STAGE_FLUSH {
                        return false;
                    }
                    slot.get_mut().buffer.extend_from_slice(payload);
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(StagedOutbound {
                        entry: Arc::clone(&entry),
                        buffer: Vec::with_capacity(STAGE_FLUSH),
                    })
                    .buffer
                    .extend_from_slice(payload);
                }
            }
        }
        let advanced = tcp.seq.wrapping_add(payload.len() as u32);
        entry.recv_nxt.store(advanced, Ordering::Release);
        let ack = crate::native_tcp::Reaction::segment(
            stamp_seq,
            advanced,
            crate::native_tcp::ctl::ACK,
            entry.window.load(Ordering::Acquire),
        );
        // The answer leaves from the address the client aimed at.
        let server = std::net::SocketAddrV4::new(ip.dst, tcp.dst_port);
        let client = std::net::SocketAddrV4::new(ip.src, tcp.src_port);
        let frame = crate::native_tcp::emit_v4(server, client, &ack, &[], &[]);
        produced.push(bytes::BytesMut::from(&frame[..]));
        true
    }

    /// The read batch's end: one write per outbound socket. A socket
    /// that refuses (a non-blocking fd the peer is not draining)
    /// keeps its staging for the next batch's retry and the flow
    /// leaves the fast path — the slot's session-side write is the
    /// route that can wait out pressure. A dead socket's staging is
    /// dropped: the flow is going away and the entry's descriptor
    /// closes with its last reference.
    pub fn flush_staged(&self) {
        let mut staged = self.staged.lock().expect("outbound staging");
        let keys: Vec<RawFd> = staged.keys().copied().collect();
        for fd in keys {
            let Some(staged_out) = staged.get_mut(&fd) else {
                continue;
            };
            match send_payload(fd, &staged_out.buffer) {
                Ok(_) => {
                    staged.remove(&fd);
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::Interrupted =>
                {
                    staged_out.entry.deactivate();
                    // The staged bytes stay for the next batch's retry.
                }
                Err(_) => {
                    staged.remove(&fd);
                }
            }
        }
    }
}

/// One socket's outbound staging: the entry (kept alive so a flush
/// under way outlives an unregister) and the bytes themselves.
struct StagedOutbound {
    entry: Arc<SpliceEntry>,
    buffer: Vec<u8>,
}

/// How much outbound staging one socket may hold before the dispatch
/// declines further claims for it: enough to amortize the write
/// syscall across a full read batch, little enough that a pressured
/// socket sheds its flow to the session path quickly.
const STAGE_FLUSH: usize = 64 * 1024;

/// Move payload bytes to the outbound socket with one write syscall
/// (the v0 lane). The splice(2) variant replaces this write with the
/// kernel pipe path once the PoC's numbers justify the pipe pair's
/// setup; both shapes skip the session channel and the relay task.
///
/// Safety lives at the call site: the fd must be a live socket that
/// this process owns.
pub fn send_payload(fd: RawFd, payload: &[u8]) -> io::Result<usize> {
    // SAFETY: write(2) on a live socket fd the process owns; the
    // buffer is a borrowed slice of the packet buffer.
    #[expect(unsafe_code)]
    let sent = unsafe { libc::write(fd, payload.as_ptr() as *const _, payload.len()) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sent as usize)
}

/// The kernel pipe path: payload into a pipe, pipe into the socket.
/// One fewer copy than `send_payload` (the pipe write is a page
/// reference, the splice is kernel-to-kernel).
pub struct PipePair {
    read_fd: RawFd,
    write_fd: RawFd,
}

impl PipePair {
    #[cfg(target_os = "linux")]
    pub fn new() -> io::Result<Self> {
        let mut fds = [0i32; 2];
        // SAFETY: pipe2(2) fills the array with two live fds owned by
        // this process.
        #[expect(unsafe_code)]
        {
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "pipes are the Linux lane",
        ))
    }

    /// Payload through the pipe into the socket: the write puts the
    /// bytes into the kernel's pipe buffer (page references), the
    /// splice moves them kernel-side to the socket.
    pub fn splice_to(&self, socket_fd: RawFd, payload: &[u8]) -> io::Result<usize> {
        // SAFETY: both fds are live and owned; the buffer is borrowed
        // for the duration of the write call only.
        #[expect(unsafe_code)]
        let written =
            unsafe { libc::write(self.write_fd, payload.as_ptr() as *const _, payload.len()) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut moved_total = 0usize;
        let mut remaining = written as usize;
        while remaining > 0 {
            let moved = splice_syscall(self.read_fd, socket_fd, remaining)?;
            moved_total += moved;
            remaining -= moved;
        }
        Ok(moved_total)
    }
}

impl Drop for PipePair {
    fn drop(&mut self) {
        // SAFETY: both fds are live and this is the last owner.
        #[expect(unsafe_code)]
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

/// Identify the payload range of a TCP-over-IPv4 packet without any
/// state machine work: just the fixed header sizes. Returns
/// (payload_start, payload_len) into the packet buffer.
pub fn payload_range(packet: &[u8]) -> Option<(usize, usize)> {
    if packet.len() < 40 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl + 20 {
        return None;
    }
    // TCP data offset (the header length in 32-bit words).
    let tcp_hlen = ((packet[ihl + 12] >> 4) as usize) * 4;
    let start = ihl + tcp_hlen;
    if packet.len() < start {
        return None;
    }
    Some((start, packet.len() - start))
}

/// The splice(2) flag for moving pages (the only mode the lane uses).
#[cfg(target_os = "linux")]
const SPLICE_F_MOVE: usize = 1;

/// The splice(2) syscall number on the architectures we ship (from
/// the kernel's syscall tables; aarch64 and x86_64 share 76 for
/// pipe-to-pipe/page movement, confirmed by strace).
#[cfg(target_os = "linux")]
const SYS_SPLICE: libc::c_long = 76;

/// splice(2) through the generic syscall(2) interface.
#[cfg(target_os = "linux")]
fn splice_syscall(pipe_fd: RawFd, socket_fd: RawFd, len: usize) -> io::Result<usize> {
    // SAFETY: the syscall moves at most `len` bytes between two live
    // kernel descriptors this process owns; the return is the count.
    #[expect(unsafe_code)]
    let moved = unsafe {
        libc::syscall(
            SYS_SPLICE,
            pipe_fd as libc::c_long,
            std::ptr::null::<libc::c_long>(),
            socket_fd as libc::c_long,
            std::ptr::null::<libc::c_long>(),
            len as libc::c_long,
            SPLICE_F_MOVE,
        )
    };
    if moved < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(moved as usize)
}

#[cfg(not(target_os = "linux"))]
fn splice_syscall(_pipe_fd: RawFd, _socket_fd: RawFd, _len: usize) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "splice is the Linux lane",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal TCP-in-IPv4 packet: valid header shapes, no options,
    /// checksums blank (neither parser nor dispatch validates them).
    #[expect(clippy::too_many_arguments)]
    fn v4_tcp_packet(
        src: std::net::Ipv4Addr,
        sport: u16,
        dst: std::net::Ipv4Addr,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut packet = Vec::with_capacity(total);
        packet.extend_from_slice(&[0x45, 0x00]);
        packet.extend_from_slice(&(total as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        packet.extend_from_slice(&src.octets());
        packet.extend_from_slice(&dst.octets());
        packet.extend_from_slice(&sport.to_be_bytes());
        packet.extend_from_slice(&dport.to_be_bytes());
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&ack.to_be_bytes());
        packet.push(5 << 4);
        packet.push(flags);
        packet.extend_from_slice(&65535u16.to_be_bytes());
        packet.extend_from_slice(&[0; 4]);
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn dispatch_moves_payload_and_declines_the_rest() {
        let lane = SpliceLane::new();
        let key = FlowKey {
            src: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 44444,
            dst: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            dst_port: 443,
            protocol: IpProtocol::Tcp,
        };
        let mut fds = [0i32; 2];
        // SAFETY: socketpair(2) fills the array with two live fds this
        // test owns.
        #[expect(unsafe_code)]
        unsafe {
            assert_eq!(
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()),
                0
            );
        }
        lane.register(key, fds[0]);
        let mut staged: Vec<bytes::BytesMut> = Vec::new();
        // Before activation the dispatch stays out of the way.
        let packet = v4_tcp_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            44444,
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            443,
            500,
            900,
            0x10,
            b"steady",
        );
        assert!(!lane.try_dispatch(&packet, &mut staged));

        let entry = lane.entry_for(&key).expect("registered");
        entry.activate(500, 900, 65535);

        // In-order current segment: claimed, cursor advanced, the
        // payload staged (nothing on the socket yet — the batch has
        // not ended).
        assert!(lane.try_dispatch(&packet, &mut staged));
        lane.flush_staged();
        let mut got = [0u8; 16];
        // SAFETY: read(2) from the test-owned peer socket.
        #[expect(unsafe_code)]
        let n = unsafe { libc::read(fds[1], got.as_mut_ptr() as *mut _, got.len()) };
        assert_eq!(n as usize, b"steady".len());
        assert_eq!(&got[..n as usize], b"steady");
        assert_eq!(entry.recv_nxt_value(), 500 + b"steady".len() as u32);
        // Exactly one answer was staged: the ACK from the server the
        // client aimed at, carrying the advanced cursor, with nothing
        // claimed-but-unanswered and nothing answered-unclaimed.
        assert_eq!(staged.len(), 1);
        let frame = &staged[0];
        let answer = TcpHeader::parse(&frame[20..]).expect("staged frame parses");
        assert_eq!(answer.0.src_port, 443);
        assert_eq!(answer.0.dst_port, 44444);
        assert_eq!(answer.0.ack, 500 + b"steady".len() as u32);
        assert!(answer.0.flags.contains(TcpFlags::ACK));
        staged.clear();

        // A gap (seq ahead) is not the dispatch's to sort.
        let gap = v4_tcp_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            44444,
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            443,
            9000,
            900,
            0x10,
            b"ahead",
        );
        assert!(!lane.try_dispatch(&gap, &mut staged));

        // A control flag (FIN) belongs to the machine.
        let fin = v4_tcp_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            44444,
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            443,
            507,
            900,
            0x11,
            b"",
        );
        assert!(!lane.try_dispatch(&fin, &mut staged));

        // A stale acknowledgment (behind SND.NXT) is the machine's
        // news, not the dispatch's.
        let stale = v4_tcp_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            44444,
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            443,
            507,
            800,
            0x10,
            b"stale",
        );
        assert!(!lane.try_dispatch(&stale, &mut staged));

        // Unregistering drops the entry; the dispatch declines and the
        // caller's fd is untouched (its dup closed with the entry).
        lane.unregister(&key);
        assert!(lane.entry_for(&key).is_none());
        assert!(!lane.try_dispatch(&packet, &mut staged));
        // SAFETY: both test sockets are ours to close.
        #[expect(unsafe_code)]
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
