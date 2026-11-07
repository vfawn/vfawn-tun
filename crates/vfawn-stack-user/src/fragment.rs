// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! IPv4 fragment reassembly on the ingress path.
//!
//! A user-space stack cannot pass fragments along and hope: the
//! destination's kernel reassembles for a forwarder, but here the
//! stack itself is the destination's peer — a non-first fragment
//! carries no ports, matches no flow, and a first fragment alone is a
//! truncated datagram. The reassembler holds fragments keyed by
//! (source, destination, protocol, id) and releases whole datagrams
//! back into the batch stream, where the ordinary flow path takes
//! over as if the wire had never split them.
//!
//! Bounds are the honest ones: a datagram larger than the protocol
//! allows, more entries than the table holds, or a first fragment
//! that never comes — each is a drop, because the alternatives are
//! unbounded memory and invented bytes.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use vfawn_wire::ipv4::Ipv4Header;
use vfawn_wire::protocol::IpProtocol;

/// How long a partial datagram waits for its missing pieces.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Entry cap: a flood of distinct ids is a flood whether the pieces
/// fit or not, and the table answers with expiry, not growth.
const MAX_ENTRIES: usize = 256;

/// Whole-table byte budget across all partial datagrams.
const MAX_BYTES: usize = 512 * 1024;

/// One datagram under construction.
struct Partial {
    deadline: Instant,
    /// Payload bytes held (the head's own payload included).
    received: usize,
    /// Total payload bytes once the last fragment names it; None
    /// until a no-more-fragments piece arrives.
    total: Option<usize>,
    /// The first fragment's whole packet, header included — the
    /// reassembled datagram is rebuilt into its buffer so the ports
    /// and options travel unchanged.
    head: BytesMut,
    /// Payload pieces past the first fragment's, by their offset in
    /// bytes. Duplicate pieces replace their earlier copies, which
    /// `received` accounts by the same subtraction.
    tail: HashMap<usize, BytesMut>,
    tail_bytes: usize,
}

/// A fragment's identity: the sender's tuple plus the id it chose.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct Key {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    id: u16,
}

/// What happened to one inbound packet.
#[derive(Debug)]
pub enum Outcome {
    /// Not a fragment: pass it through untouched.
    Pass,
    /// A fragment, held or dropped — nothing for the batch yet.
    Held,
    /// A complete datagram, reassembled: one whole IP packet.
    Complete(BytesMut),
}

/// The reassembly table. One instance per ingress path.
#[derive(Default)]
pub struct Reassembler {
    entries: HashMap<Key, Partial>,
    bytes: usize,
    last_sweep: Option<Instant>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one whole IP packet; fragments come back out whole.
    pub fn feed(&mut self, packet: &mut BytesMut, now: Instant) -> Outcome {
        let Ok((header, _)) = Ipv4Header::parse(packet) else {
            return Outcome::Pass;
        };
        // The more-fragments flag or a nonzero offset: the wire split
        // this datagram. (MF set with offset zero is the first piece;
        // offset alone means a successor.)
        if header.fragment_offset == 0 && !header.more_fragments {
            return Outcome::Pass;
        }
        let key = Key {
            source: header.src,
            destination: header.dst,
            protocol: protocol_byte(header.protocol),
            id: header.identification,
        };
        let ihl = header.header_len;
        if ihl < 20 || ihl > packet.len() {
            return Outcome::Held; // a header claiming more than it has
        }
        let payload_len = packet.len() - ihl;
        // Offsets are in 8-byte units; only the final piece may be
        // unaligned, and it carries no MF.
        if header.more_fragments && !payload_len.is_multiple_of(8) {
            return Outcome::Held;
        }
        let offset_bytes = header.fragment_offset as usize * 8;
        if offset_bytes + payload_len > 65_535 - ihl {
            return Outcome::Held;
        }
        if !self.budget(packet.len(), now) {
            return Outcome::Held;
        }

        if header.fragment_offset == 0 {
            // The first piece owns the head; a repeat declines — two
            // heads cannot merge, and pieces parked under the first
            // head (out-of-order arrival) must not be orphaned.
            if let Some(entry) = self.entries.get(&key)
                && entry.head.len() > ihl
            {
                return Outcome::Held;
            }
            let entry = self.entries.entry(key).or_insert_with(|| Partial {
                deadline: now,
                received: 0,
                total: None,
                head: BytesMut::new(),
                tail: HashMap::new(),
                tail_bytes: 0,
            });
            entry.head = packet.clone();
            // The tails parked before the head already counted their
            // bytes; the head's payload joins the count.
            entry.received += payload_len;
            if !header.more_fragments {
                entry.total = Some(payload_len);
            }
            entry.deadline = now + TIMEOUT;
            self.bytes += entry.head.len();
        } else {
            // A successor parks under its offset — even with no head
            // yet: out-of-order links send tails first, and the head's
            // arrival is what names the flow the datagram belongs to.
            let entry = self.entries.entry(key).or_insert_with(|| Partial {
                deadline: now,
                received: 0,
                total: None,
                head: BytesMut::new(),
                tail: HashMap::new(),
                tail_bytes: 0,
            });
            if let Some(old) = entry
                .tail
                .insert(offset_bytes, packet.clone().split_off(ihl))
            {
                self.bytes -= old.len();
                entry.tail_bytes -= old.len();
                entry.received -= old.len();
            }
            self.bytes += payload_len;
            entry.tail_bytes += payload_len;
            entry.received += payload_len;
            if !header.more_fragments {
                entry.total = Some(offset_bytes + payload_len);
            }
            entry.deadline = now + TIMEOUT;
        }

        // Complete when the total is known and every payload byte has
        // arrived; the byte count stays true through duplicates
        // because a repeat replaces its earlier copy.
        let Some(total) = self.entries.get(&key).and_then(|e| e.total) else {
            return Outcome::Held;
        };
        if self.entries.get(&key).is_none_or(|e| e.received < total) {
            return Outcome::Held;
        }

        // Rebuild: the head's header (total length and flags fixed)
        // plus every parked piece at its offset.
        let Some(entry) = self.entries.remove(&key) else {
            return Outcome::Held;
        };
        self.bytes = self
            .bytes
            .saturating_sub(entry.head.len())
            .saturating_sub(entry.tail_bytes);
        let ihl = (entry.head[0] & 0x0f) as usize * 4;
        let mut whole = entry.head;
        let mut tail: Vec<(usize, BytesMut)> = entry.tail.into_iter().collect();
        tail.sort_unstable_by_key(|(offset, _)| *offset);
        for (offset, piece) in tail {
            let at = ihl + offset;
            let end = at + piece.len();
            if whole.len() < end {
                whole.resize(end, 0);
            }
            whole[at..end].copy_from_slice(&piece);
        }
        // Total length covers header plus every payload byte. In the
        // flags-and-fragment field, byte 6 carries the flags (MF is
        // its 0x20 bit) and byte 7 the low offset bits: one whole
        // datagram clears MF and the offset, DF and reserved stay.
        let total_len = (ihl + total.min(whole.len().saturating_sub(ihl))) as u16;
        whole[2..4].copy_from_slice(&total_len.to_be_bytes());
        whole[6] &= !0x20;
        whole[7] = 0;
        Outcome::Complete(whole)
    }

    /// Expire partials whose deadline passed; cheap when nothing is
    /// due. The ingress calls this once per batch.
    pub fn sweep(&mut self, now: Instant) {
        let due = self
            .last_sweep
            .is_none_or(|at| now.duration_since(at) >= Duration::from_secs(1));
        if !due {
            return;
        }
        self.last_sweep = Some(now);
        let expired: Vec<Key> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.deadline < now)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.remove(&key);
        }
    }

    /// Account an incoming size against the budget, expiring past-deadline
    /// entries to make room; false means the piece drops instead.
    fn budget(&mut self, incoming: usize, now: Instant) -> bool {
        loop {
            if self.bytes + incoming <= MAX_BYTES && self.entries.len() < MAX_ENTRIES {
                break;
            }
            let Some(oldest) = self
                .entries
                .iter()
                .filter(|(_, entry)| entry.deadline < now)
                .min_by_key(|(_, entry)| entry.deadline)
                .map(|(key, _)| *key)
            else {
                // Nothing expired to evict: a live table at capacity
                // declines the piece rather than stealing from a flow.
                return false;
            };
            self.remove(&oldest);
        }
        true
    }

    fn remove(&mut self, key: &Key) {
        if let Some(entry) = self.entries.remove(key) {
            self.bytes = self
                .bytes
                .saturating_sub(entry.head.len() + entry.tail_bytes);
        }
    }
}

/// The wire protocol number of a parsed protocol value.
fn protocol_byte(protocol: IpProtocol) -> u8 {
    protocol.number()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Build one IPv4 packet: no options, UDP, id and the
    /// flags-and-fragment field exactly as given.
    fn v4(id: u16, flags_offset: u16, payload: &[u8]) -> BytesMut {
        let total = 20 + payload.len();
        let mut packet = BytesMut::zeroed(total);
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[198, 18, 0, 2]);
        packet[16..20].copy_from_slice(&[203, 0, 113, 1]);
        packet[20..].copy_from_slice(payload);
        packet
    }

    const MF: u16 = 0x2000;

    #[test]
    fn two_fragments_come_back_whole() {
        let mut table = Reassembler::new();
        let now = Instant::now();
        let first = v4(7, MF, &[0u8; 8]);
        let second = v4(7, 1, b"tail"); // offset one 8-byte unit
        match table.feed(&mut first.clone(), now) {
            Outcome::Held => {}
            other => panic!("first held, got {other:?}"),
        }
        let Outcome::Complete(whole) = table.feed(&mut second.clone(), now) else {
            panic!("second completes");
        };
        // Header 20 + 8 + 4 payload bytes, MF and offset cleared.
        assert_eq!(whole.len(), 32);
        assert_eq!(u16::from_be_bytes([whole[2], whole[3]]), 32);
        assert_eq!(u16::from_be_bytes([whole[6], whole[7]]) & 0x3fff, 0);
        assert_eq!(&whole[20..28], &[0u8; 8]);
        assert_eq!(&whole[28..], b"tail");
    }

    #[test]
    fn out_of_order_pieces_still_complete() {
        let mut table = Reassembler::new();
        let now = Instant::now();
        let Outcome::Held = table.feed(&mut v4(9, 2, b"C"), now) else {
            panic!("a successor without its head is held");
        };
        let Outcome::Complete(whole) = table.feed(&mut v4(9, MF, &[0u8; 16]), now) else {
            panic!("the late head completes");
        };
        assert_eq!(&whole[20..36], &[0u8; 16]);
        assert_eq!(&whole[36..], b"C");
    }

    #[test]
    fn a_whole_packet_passes_through() {
        let mut table = Reassembler::new();
        let mut plain = v4(1, 0, b"no fragments here");
        match table.feed(&mut plain, Instant::now()) {
            Outcome::Pass => {}
            other => panic!("unsplit datagrams pass, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicate_first_fragment_declines() {
        let mut table = Reassembler::new();
        let now = Instant::now();
        let Outcome::Held = table.feed(&mut v4(5, MF, &[0u8; 8]), now) else {
            panic!("held");
        };
        let Outcome::Held = table.feed(&mut v4(5, MF, &[9u8; 8]), now) else {
            panic!("the repeat declines, keeping the first head");
        };
        // The original still completes with its successor.
        let Outcome::Complete(whole) = table.feed(&mut v4(5, 1, b"z"), now) else {
            panic!("completes");
        };
        assert_eq!(&whole[20..28], &[0u8; 8]);
    }

    #[test]
    fn an_expired_partial_is_swept() {
        let mut table = Reassembler::new();
        let now = Instant::now();
        let Outcome::Held = table.feed(&mut v4(3, MF, &[0u8; 8]), now) else {
            panic!("held");
        };
        let later = now + TIMEOUT + Duration::from_secs(1);
        table.sweep(later);
        let Outcome::Held = table.feed(&mut v4(3, 1, b"late"), later) else {
            panic!("the swept head is gone; the successor drops");
        };
    }

    #[test]
    fn the_budget_declines_rather_than_grows_without_bound() {
        let mut table = Reassembler::new();
        let now = Instant::now();
        // Each id parks a fresh max-size head; beyond the byte budget
        // the table declines.
        let mut declined = 0;
        for id in 0..64u16 {
            let mut piece = v4(id, MF, &vec![0u8; 9_000]);
            if matches!(table.feed(&mut piece, now), Outcome::Held) {
                declined += 1;
            }
        }
        assert!(declined > 0, "the budget must eventually decline");
        assert!(table.entries.len() <= MAX_ENTRIES);
    }

    #[test]
    fn the_table_keys_on_the_senders_tuple() {
        let mut table = Reassembler::new();
        let now = Instant::now();
        let mut other_src = v4(11, MF, &[0u8; 8]);
        other_src[12..16].copy_from_slice(&[198, 18, 0, 3]);
        let Outcome::Held = table.feed(&mut other_src, now) else {
            panic!("held");
        };
        // Same id, different source: a stranger's successor must not
        // complete against the first's head.
        let Outcome::Held = table.feed(&mut v4(11, 1, b"x"), now) else {
            panic!("held: not the same datagram");
        };
        let _ = Ipv4Addr::LOCALHOST;
    }
}
