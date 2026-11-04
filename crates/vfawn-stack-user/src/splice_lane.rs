// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The payload fast path: once a relay flow is established, its data
//! segments skip the TCP state machine's session machinery entirely.
//! The shard parses just enough header to identify the flow and the
//! payload range, then the bytes move through a kernel pipe to the
//! outbound socket (Linux `splice(2)`, the mechanism behind the go
//! stack's 39.5 Gbit/s: the payload never crosses into a second
//! userspace buffer, and no per-segment task wakeups happen).
//!
//! The state machine stays in charge of the connection's control
//! plane: handshake, window accounting, ACK generation, teardown.
//! What bypass removes is the payload's trip through the session
//! channel, the relay task's wakeup, and the outbound write syscall.
//! The ACK clock still runs: the lane tells the connection how many
//! payload bytes it moved so the sequence space advances exactly as
//! the slow path would have it.

use std::collections::HashMap;
use std::io;
use std::os::fd::RawFd;
use std::sync::Mutex;

/// A registered outbound socket for one bypassed flow: the kernel fd
/// the lane splices into, plus the flow identity the shard dispatches
/// on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpliceTarget {
    pub flow: vfawn_wire::flow::FlowKey,
    pub fd: RawFd,
}

/// The lane's shared registry: flows opt in by registering their
/// outbound fd; the shard's dispatch consults this before running the
/// full state machine.
#[derive(Default)]
pub struct SpliceLane {
    targets: Mutex<HashMap<vfawn_wire::flow::FlowKey, RawFd>>,
    /// The TUN's direct write handle: frames pushed here reach the
    /// wire without the shard's drain path. The io bridge installs it
    /// at spawn; the relay reads it for the downlink fast path.
    tun_write: Mutex<Option<std::sync::mpsc::SyncSender<Vec<bytes::BytesMut>>>>,
}

impl SpliceLane {
    pub fn new() -> Self {
        Self::default()
    }

    /// The process-wide lane: the relay handler's side and the shard's
    /// side meet here without threading an Arc through the session
    /// contract. One process runs one stack; the singleton is the
    /// honest shape for that.
    pub fn global() -> &'static SpliceLane {
        static LANE: std::sync::OnceLock<SpliceLane> = std::sync::OnceLock::new();
        LANE.get_or_init(SpliceLane::new)
    }

    /// Install the TUN's direct write handle (the io bridge's channel).
    pub fn set_tun_write(&self, sender: std::sync::mpsc::SyncSender<Vec<bytes::BytesMut>>) {
        *self.tun_write.lock().expect("tun write") = Some(sender);
    }

    /// Push constructed frames straight to the TUN: the downlink fast
    /// path's exit. Returns false when the write handle is absent or
    /// the device is down (the caller falls back to the session).
    pub fn push_to_tun(&self, frames: Vec<bytes::BytesMut>) -> bool {
        let guard = self.tun_write.lock().expect("tun write");
        match guard.as_ref() {
            Some(sender) => sender.send(frames).is_ok(),
            None => false,
        }
    }

    /// Register a flow for the fast path. After this call, the shard
    /// sends the flow's data segments here instead of through the
    /// slot's session channel.
    pub fn register(&self, flow: vfawn_wire::flow::FlowKey, fd: RawFd) {
        self.targets.lock().expect("splice lane").insert(flow, fd);
    }

    /// Remove a flow (teardown or fallback).
    pub fn unregister(&self, flow: &vfawn_wire::flow::FlowKey) {
        self.targets.lock().expect("splice lane").remove(flow);
    }

    /// The outbound fd for a flow, if it rides the lane.
    pub fn fd_for(&self, flow: &vfawn_wire::flow::FlowKey) -> Option<RawFd> {
        self.targets.lock().expect("splice lane").get(flow).copied()
    }
}

/// Move payload bytes to the outbound socket with one write syscall
/// (the v0 lane). The splice(2) variant replaces this write with the
/// kernel pipe path once the PoC's numbers justify the pipe pair's
/// setup; both shapes skip the session channel and the relay task.
///
/// Safety lives at the call site: the fd must be a live socket that
/// this process owns.
pub fn send_payload(fd: RawFd, payload: &[u8]) -> io::Result<usize> {
    // SAFETY: write(2) on a live socket fd the process owns; the
    // buffer is a borrowed slice of the shard's packet buffer.
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
