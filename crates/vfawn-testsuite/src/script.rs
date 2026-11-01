// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Packet scripting: build the exact packets a scripted client sends,
//! with correct checksums and no randomness.
//!
//! Integration tests drive a stack through these builders the way a
//! kernel would: SYN, ACK, data, FIN, each one a byte-exact packet the
//! parsers in vfawn-wire accept. Sharing them keeps every suite on the
//! same wire format instead of each growing its own copy.

use std::net::{Ipv4Addr, SocketAddrV4};

/// A scripted client talking to one server address.
pub struct Script {
    client: SocketAddrV4,
    server: SocketAddrV4,
}

impl Script {
    pub fn new(client: SocketAddrV4, server: SocketAddrV4) -> Self {
        Self { client, server }
    }

    /// A minimal IPv4+TCP packet with the given flags and payload.
    pub fn tcp(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20 + 20 + payload.len());

        // IPv4 header (RFC 791): 20 bytes, protocol 6.
        packet.extend_from_slice(&[0x45, 0x00]);
        packet.extend_from_slice(&((20 + 20 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // id, flags
        packet.extend_from_slice(&[64, 0x06]); // ttl, proto
        packet.extend_from_slice(&[0x00, 0x00]); // checksum, fixed below
        packet.extend_from_slice(&self.client.ip().octets());
        packet.extend_from_slice(&self.server.ip().octets());

        // TCP header (RFC 9293): 20 bytes.
        packet.extend_from_slice(&self.client.port().to_be_bytes());
        packet.extend_from_slice(&self.server.port().to_be_bytes());
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&ack.to_be_bytes());
        packet.push(0x50); // data offset 5, no options
        packet.push(flags);
        packet.extend_from_slice(&0xffffu16.to_be_bytes()); // window
        packet.extend_from_slice(&[0x00, 0x00]); // checksum, fixed below
        packet.extend_from_slice(&[0x00, 0x00]); // urgent

        // The payload joins the packet before any checksum runs: the
        // transport checksum covers it, and computing it over the bare
        // header happened to pass only for all-zero payloads, which is
        // how the bug survived every zero-filled consumer until a stack
        // that verifies checksums met a nonzero one.
        packet.extend_from_slice(payload);

        let ipv4_sum = checksum(&packet[..20]);
        packet[10] = (ipv4_sum >> 8) as u8;
        packet[11] = ipv4_sum as u8;

        let pseudo = pseudo_header(
            self.client.ip(),
            self.server.ip(),
            6,
            (20 + payload.len()) as u32,
        );
        let segment_sum = checksum_with_carry(pseudo, &packet[20..]);
        packet[36] = (segment_sum >> 8) as u8;
        packet[37] = segment_sum as u8;
        packet
    }

    /// A minimal IPv4+UDP datagram from the client to the server.
    pub fn udp(&self, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20 + 8 + payload.len());

        // IPv4 header (RFC 791): 20 bytes, protocol 17.
        packet.extend_from_slice(&[0x45, 0x00]);
        packet.extend_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        packet.extend_from_slice(&[64, 0x11]); // ttl, proto
        packet.extend_from_slice(&[0x00, 0x00]); // checksum, fixed below
        packet.extend_from_slice(&self.client.ip().octets());
        packet.extend_from_slice(&self.server.ip().octets());

        // UDP header (RFC 768): 8 bytes.
        packet.extend_from_slice(&self.client.port().to_be_bytes());
        packet.extend_from_slice(&self.server.port().to_be_bytes());
        packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]); // checksum, fixed below

        packet.extend_from_slice(payload);

        let ipv4_sum = checksum(&packet[..20]);
        packet[10] = (ipv4_sum >> 8) as u8;
        packet[11] = ipv4_sum as u8;

        let pseudo = pseudo_header(
            self.client.ip(),
            self.server.ip(),
            17,
            (8 + payload.len()) as u32,
        );
        let datagram_sum = checksum_with_carry(pseudo, &packet[20..]);
        packet[26] = (datagram_sum >> 8) as u8;
        packet[27] = datagram_sum as u8;

        packet
    }
}

/// Reverse the direction of a stack-emitted TCP packet so a mock device
/// can feed it back as if the client had sent the response. Swaps
/// addresses and ports and recomputes both checksums.
pub fn reverse_tcp(packet: &[u8]) -> Vec<u8> {
    if packet.len() < 40 {
        return packet.to_vec();
    }
    let mut reversed = packet.to_vec();
    reversed.swap(12, 16);
    reversed.swap(13, 17);
    reversed.swap(14, 18);
    reversed.swap(15, 19);
    reversed.swap(20, 22);
    reversed.swap(21, 23);
    let ipv4_sum = checksum(&reversed[..20]);
    reversed[10] = (ipv4_sum >> 8) as u8;
    reversed[11] = ipv4_sum as u8;
    let pseudo = pseudo_header(
        &Ipv4Addr::new(reversed[12], reversed[13], reversed[14], reversed[15]),
        &Ipv4Addr::new(reversed[16], reversed[17], reversed[18], reversed[19]),
        6,
        (reversed.len() - 20) as u32,
    );
    let tcp_sum = checksum_with_carry(pseudo, &reversed[20..]);
    reversed[36] = (tcp_sum >> 8) as u8;
    reversed[37] = tcp_sum as u8;
    reversed
}

fn checksum(data: &[u8]) -> u16 {
    !fold(sum_words(data))
}

fn checksum_with_carry(carry: u32, data: &[u8]) -> u16 {
    !fold(carry + sum_words(data))
}

fn sum_words(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < data.len() {
        sum += u16::from_be_bytes([data[index], data[index + 1]]) as u32;
        index += 2;
    }
    if index < data.len() {
        sum += (data[index] as u32) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn pseudo_header(src: &Ipv4Addr, dst: &Ipv4Addr, protocol: u8, length: u32) -> u32 {
    let mut sum = 0u32;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += protocol as u32;
    sum += length;
    sum
}
