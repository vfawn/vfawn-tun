// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Deterministic replay: pcap in, packet-sequence assertions out.
//!
//! Each test loads a pcap file through `PcapDevice`, drives it through
//! vfawn-wire's parsers, and asserts on the parsed semantics (flags,
//! sequence numbers, protocol identity). Running the same file twice must
//! produce identical results: the input has no timing dependence.

use bytes::BytesMut;
use std::path::Path;
use vfawn_core::PacketDevice;
use vfawn_testsuite::PcapDevice;
use vfawn_wire::IpProtocol;
use vfawn_wire::flow::{flow_key, fragment_info};
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::tcp::TcpHeader;

fn pcap(name: &str) -> PcapDevice {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps")
        .join(name);
    PcapDevice::from_file(&path).expect("load pcap")
}

/// One parsed packet from a replay, with the fields assertions care about.
struct Observed {
    version: u8,
    protocol: IpProtocol,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    is_fragment: bool,
}

fn observe_all(device: &mut PcapDevice) -> Vec<Observed> {
    let mut seen = Vec::new();
    let mut bufs = vec![BytesMut::new(); 8];
    loop {
        let count = device.read_batch(&mut bufs).unwrap();
        if count == 0 {
            break;
        }
        for buf in bufs.iter().take(count) {
            let version = buf[0] >> 4;
            if version != 4 {
                seen.push(Observed {
                    version,
                    protocol: IpProtocol::Other(0),
                    src_port: 0,
                    dst_port: 0,
                    flags: 0,
                    seq: 0,
                    ack: 0,
                    is_fragment: false,
                });
                continue;
            }
            let (ip, payload) = Ipv4Header::parse(buf).expect("parse IPv4");
            let frag = fragment_info(buf).is_some();

            let mut ports = (0, 0);
            let mut tcp = (0u8, 0u32, 0u32);
            match ip.protocol {
                IpProtocol::Tcp => {
                    if let Ok((h, _)) = TcpHeader::parse(payload) {
                        ports = (h.src_port, h.dst_port);
                        tcp = (h.flags.bits(), h.seq, h.ack);
                    }
                }
                IpProtocol::Udp => {
                    if payload.len() >= 4 {
                        ports = (
                            u16::from_be_bytes([payload[0], payload[1]]),
                            u16::from_be_bytes([payload[2], payload[3]]),
                        );
                    }
                }
                _ => {}
            }

            seen.push(Observed {
                version,
                protocol: ip.protocol,
                src_port: ports.0,
                dst_port: ports.1,
                flags: tcp.0,
                seq: tcp.1,
                ack: tcp.2,
                is_fragment: frag,
            });
        }
    }
    seen
}

#[test]
fn tcp_lifecycle_packets_parse_in_capture_order() {
    let mut device = pcap("tcp_lifecycle.pcap");
    assert_eq!(device.remaining(), 7);

    let packets = observe_all(&mut device);
    assert_eq!(packets.len(), 7);

    // SYN (client to server)
    assert_eq!(packets[0].protocol, IpProtocol::Tcp);
    assert_eq!(packets[0].src_port, 45678);
    assert_eq!(packets[0].dst_port, 443);
    assert_eq!(packets[0].flags & 0x02, 0x02); // SYN set
    assert_eq!(packets[0].flags & 0x10, 0x00); // ACK clear
    assert_eq!(packets[0].seq, 1000);

    // SYN-ACK (server to client)
    assert_eq!(packets[1].src_port, 443);
    assert_eq!(packets[1].dst_port, 45678);
    assert_eq!(packets[1].flags & 0x02, 0x02);
    assert_eq!(packets[1].flags & 0x10, 0x10);
    assert_eq!(packets[1].seq, 2000);
    assert_eq!(packets[1].ack, 1001);

    // ACK (handshake complete)
    assert_eq!(packets[2].flags & 0x10, 0x10);
    assert_eq!(packets[2].flags & 0x02, 0x00);
    assert_eq!(packets[2].ack, 2001);

    // PSH+ACK with data
    assert_eq!(packets[3].flags & 0x08, 0x08);
    assert_eq!(packets[3].seq, 1001);

    // Pure ACK from the server
    assert_eq!(packets[4].flags, 0x10);
    assert_eq!(packets[4].ack, 1012);

    // FIN+ACK from the client
    assert_eq!(packets[5].flags & 0x01, 0x01);

    // FIN+ACK from the server
    assert_eq!(packets[6].flags & 0x01, 0x01);
}

#[test]
fn replay_is_deterministic_across_runs() {
    // Load the same file twice; both runs must produce the same sequence.
    let first = observe_all(&mut pcap("tcp_lifecycle.pcap"));
    let second = observe_all(&mut pcap("tcp_lifecycle.pcap"));

    assert_eq!(first.len(), second.len());
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(a.version, b.version);
        assert_eq!(a.protocol, b.protocol);
        assert_eq!(a.src_port, b.src_port);
        assert_eq!(a.dst_port, b.dst_port);
        assert_eq!(a.flags, b.flags);
        assert_eq!(a.seq, b.seq);
        assert_eq!(a.ack, b.ack);
    }
}

#[test]
fn fragments_are_identified_but_yield_no_flow_key() {
    let mut device = pcap("ipv4_fragments.pcap");
    assert_eq!(device.remaining(), 3);

    let packets = observe_all(&mut device);
    assert_eq!(packets.len(), 3);

    // Every packet is a fragment.
    for (i, p) in packets.iter().enumerate() {
        assert!(
            p.is_fragment,
            "packet {i} should be identified as a fragment"
        );
    }

    // Non-first fragments carry no transport header, so no flow key.
    let mut device = pcap("ipv4_fragments.pcap");
    let mut bufs = vec![BytesMut::new(); 1];
    let mut flow_keys = 0;
    let mut frag_keys = 0;
    loop {
        let count = device.read_batch(&mut bufs).unwrap();
        if count == 0 {
            break;
        }
        for buf in bufs.iter().take(count) {
            if flow_key(buf).is_some() {
                flow_keys += 1;
            }
            if fragment_info(buf).is_some() {
                frag_keys += 1;
            }
        }
    }
    // The first fragment has a partial TCP header (8 bytes: ports only,
    // enough for flow_key if it reaches the TCP parser with 20 bytes of
    // header, which 8 bytes of fragment payload does not satisfy).
    // The behavior we assert: fragment_info finds all three, flow_key
    // finds none (fragments are too short for a full TCP header).
    assert_eq!(frag_keys, 3, "all three fragments identified");
    assert_eq!(flow_keys, 0, "no flow keys from fragment payloads");
}

#[test]
fn mixed_traffic_separates_flows_from_fragments() {
    let mut device = pcap("mixed.pcap");
    let packets = observe_all(&mut device);
    assert_eq!(packets.len(), 5);

    // SYN (not a fragment)
    assert!(!packets[0].is_fragment);
    assert_eq!(packets[0].protocol, IpProtocol::Tcp);

    // Two fragments
    assert!(packets[1].is_fragment);
    assert!(packets[2].is_fragment);

    // UDP (not a fragment)
    assert!(!packets[3].is_fragment);
    assert_eq!(packets[3].protocol, IpProtocol::Udp);
    assert_eq!(packets[3].dst_port, 53);

    // SYN-ACK
    assert!(!packets[4].is_fragment);
    assert_eq!(packets[4].protocol, IpProtocol::Tcp);
}

#[test]
fn udp_packet_yields_flow_key() {
    let mut device = pcap("udp_simple.pcap");
    let mut bufs = vec![BytesMut::new(); 1];
    let count = device.read_batch(&mut bufs).unwrap();
    assert_eq!(count, 1);

    let key = flow_key(&bufs[0]).expect("UDP flow key");
    assert_eq!(key.src_port, 50000);
    assert_eq!(key.dst_port, 53);
    assert_eq!(key.protocol, IpProtocol::Udp);
    assert!(!key.src.is_unspecified());
}
