// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The oracle side of the differential bed: the same scenario run by
//! smoltcp (0BSD, consumed unmodified from crates.io, version pinned to
//! the refer checkout).
//!
//! The driver plays the server: one TCP socket listening on the
//! scenario's server port, an echo application behind it (whatever it
//! receives once established, it sends back), and a virtual clock the
//! runner steps through. Injected packets arrive through a loopback
//! device the interface borrows during poll; emitted packets are
//! captured at the transmit token and parsed into records with
//! vfawn-wire, so what gets compared is wire truth, not the stack's
//! internal narration.

use std::collections::VecDeque;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use crate::diff::{Scenario, SegmentRecord, StackDriver, Step};

/// The loopback smoltcp talks to during poll: injected queue in,
/// emitted queue out. smoltcp 0.14 borrows the device per call, so the
/// queues live with the driver and need no sharing tricks.
#[derive(Default)]
struct LoopDevice {
    injected: VecDeque<Vec<u8>>,
    emitted: Vec<Vec<u8>>,
}

struct LoopRx {
    frame: Vec<u8>,
}

impl RxToken for LoopRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.frame)
    }
}

struct LoopTx;

impl TxToken for LoopTx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        PENDING_TX.with(|tx| tx.borrow_mut().push(buffer));
        result
    }
}

// The transmit token cannot borrow the device (smoltcp hands it out
// before the device is borrowed again), so emitted frames pass through
// this thread-local hand-off that `poll` drains right after.
thread_local! {
    static PENDING_TX: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl Device for LoopDevice {
    type RxToken<'a> = LoopRx;
    type TxToken<'a> = LoopTx;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.injected.pop_front()?;
        Some((LoopRx { frame }, LoopTx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(LoopTx)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

/// Echo application state: bytes received and not yet sent back.
struct EchoApp {
    backlog: Vec<Vec<u8>>,
}

impl EchoApp {
    fn new() -> Self {
        Self {
            backlog: Vec::new(),
        }
    }

    /// Run against the socket: pull what arrived, push what fits.
    fn pump(&mut self, socket: &mut TcpSocket) {
        if !socket.is_active() {
            self.backlog.clear();
            return;
        }
        let mut chunk = [0u8; 4096];
        while socket.can_recv() {
            match socket.recv_slice(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => self.backlog.push(chunk[..n].to_vec()),
            }
        }
        let mut index = 0;
        while index < self.backlog.len() && socket.can_send() {
            let data = &self.backlog[index];
            match socket.send_slice(data) {
                Ok(0) => break,
                Ok(n) if n == data.len() => index += 1,
                Ok(_) => break,
                Err(_) => break,
            }
        }
        self.backlog.drain(..index);
    }
}

/// The smoltcp oracle driver.
pub struct SmoltcpDriver {
    /// The ISN the oracle drew for this scenario's connection, read off
    /// its first SYN-ACK; the differential corpus needs the value both
    /// sides acknowledge.
    pub listen_isn: Option<u32>,
    device: LoopDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: SocketHandle,
    now_ms: u64,
    listen_port: u16,
    app: EchoApp,
}

impl SmoltcpDriver {
    pub fn new() -> Self {
        let device = LoopDevice::default();
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut LoopDevice::default(), Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(192, 0, 2, 200), 24))
                .ok();
        });
        let rx = SocketBuffer::new(vec![0; 128 * 1024]);
        let tx = SocketBuffer::new(vec![0; 128 * 1024]);
        let socket = TcpSocket::new(rx, tx);
        let mut sockets = SocketSet::new(vec![]);
        let tcp = sockets.add(socket);
        Self {
            listen_isn: None,
            device,
            iface,
            sockets,
            tcp,
            now_ms: 0,
            listen_port: 0,
            app: EchoApp::new(),
        }
    }

    /// Poll until the stack is quiet, with the echo application running
    /// between rounds: receive what arrived, queue it back, send what
    /// the window allows, until a round changes nothing.
    fn pump(&mut self) {
        for _ in 0..64 {
            let now = Instant::from_millis(self.now_ms as i64);
            let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
            self.drain_emitted();
            {
                let socket = self.sockets.get_mut::<TcpSocket>(self.tcp);
                self.app.pump(socket);
            }
            let quiet = matches!(
                self.iface.poll(now, &mut self.device, &mut self.sockets),
                smoltcp::iface::PollResult::None
            );
            self.drain_emitted();
            if quiet {
                break;
            }
        }
    }

    fn drain_emitted(&mut self) {
        PENDING_TX.with(|tx| {
            let pending = std::mem::take(&mut *tx.borrow_mut());
            self.device.emitted.extend(pending);
        });
    }
}

impl Default for SmoltcpDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl StackDriver for SmoltcpDriver {
    fn reset(&mut self, scenario: &Scenario) {
        let mut device = LoopDevice::default();
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            let octets = scenario.server.ip().octets();
            addrs
                .push(IpCidr::new(
                    IpAddress::v4(octets[0], octets[1], octets[2], octets[3]),
                    24,
                ))
                .ok();
        });
        let rx = SocketBuffer::new(vec![0; 128 * 1024]);
        let tx = SocketBuffer::new(vec![0; 128 * 1024]);
        let mut socket = TcpSocket::new(rx, tx);
        socket
            .listen(scenario.server.port())
            .expect("oracle listen");
        let mut sockets = SocketSet::new(vec![]);
        let tcp = sockets.add(socket);

        self.device = device;
        self.iface = iface;
        self.sockets = sockets;
        self.tcp = tcp;
        self.now_ms = 0;
        self.listen_port = scenario.server.port();
        self.listen_isn = None;
        self.app = EchoApp::new();
    }

    fn step(&mut self, step: &Step) -> Vec<SegmentRecord> {
        match step {
            Step::Inject { delay_ms, packet } => {
                self.now_ms += delay_ms;
                self.device.injected.push_back(packet.clone());
                self.pump();
            }
            Step::Wait { delay_ms } => {
                self.now_ms += delay_ms;
                self.pump();
            }
        }
        self.drain()
    }

    fn finish(&mut self) -> Vec<SegmentRecord> {
        // Let late retransmissions and timers speak before judging.
        for _ in 0..4 {
            self.now_ms += 250;
            self.pump();
        }
        self.drain()
    }
}

impl SmoltcpDriver {
    fn drain(&mut self) -> Vec<SegmentRecord> {
        let frames: Vec<Vec<u8>> = std::mem::take(&mut self.device.emitted);
        let records: Vec<SegmentRecord> = frames
            .iter()
            .filter_map(|frame| parse_record(frame, self.now_ms))
            .collect();
        if self.listen_isn.is_none()
            && let Some(record) = records.first()
            && record.flags & 0x12 == 0x12
        {
            self.listen_isn = Some(record.seq);
        }
        records
    }
}

/// Wire truth extraction: only what a peer could observe.
fn parse_record(frame: &[u8], at_ms: u64) -> Option<SegmentRecord> {
    let (ip, payload) = vfawn_wire::ipv4::Ipv4Header::parse(frame).ok()?;
    if ip.protocol != vfawn_wire::protocol::IpProtocol::Tcp {
        return None;
    }
    let (tcp, seg_payload) = vfawn_wire::tcp::TcpHeader::parse(payload).ok()?;
    Some(SegmentRecord {
        at_ms,
        seq: tcp.seq,
        ack: tcp.ack,
        flags: tcp.flags.bits(),
        window: tcp.window,
        payload_len: seg_payload.len(),
    })
}
