// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! IPv4 fragmentation on the egress path.
//!
//! A user-space stack hands the device complete datagrams; some
//! devices decline anything larger than their MTU (wintun's ring is
//! MTU-sized), and the IP contract says a datagram that does not fit
//! leaves as fragments. The splitter takes one whole IPv4 packet and
//! yields MTU-fitting pieces: the first carries the original header
//! (MF set), the successors carry copies of it with their own
//! offsets, and every piece's total length and header checksum are
//! its own.
//!
//! Only datagrams the sender marked fragmentable split: a set DF bit
//! is the sender's own instruction that the datagram would rather die
//! than split, and honoring it is the whole point of the bit.

use crate::checksum;

/// Split one whole IPv4 packet into pieces of at most `mtu` bytes.
/// Returns None when the packet is not IPv4, already fits, asks not
/// to be fragmented, or is malformed.
pub fn split(packet: &[u8], mtu: usize) -> Option<Vec<Vec<u8>>> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] as usize & 0x0f) * 4;
    if ihl < 20 || ihl > packet.len() {
        return None;
    }
    // Reserved bit (0x8000) is corruption per RFC 791; DF (0x4000) is
    // the sender's refusal; an offset with a whole packet is not one.
    let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_offset & 0x8000 != 0 || flags_offset & 0x4000 != 0 || flags_offset & 0x1fff != 0 {
        return None;
    }
    if packet.len() <= mtu {
        return None;
    }
    // Payload must ride in 8-byte units per piece; the last piece
    // takes the remainder. A piece carries at least one unit.
    let payload_per_piece = mtu.saturating_sub(ihl) & !7;
    if payload_per_piece == 0 {
        return None;
    }
    let payload = &packet[ihl..];
    let mut pieces = Vec::new();
    let mut offset = 0usize;
    loop {
        let take = payload_per_piece.min(payload.len() - offset);
        let more = offset + take < payload.len();
        let mut piece = Vec::with_capacity(ihl + take);
        piece.extend_from_slice(&packet[..ihl]);
        piece.extend_from_slice(&payload[offset..offset + take]);
        let total = (ihl + take) as u16;
        piece[2..4].copy_from_slice(&total.to_be_bytes());
        // MF set on every piece but the last; the offset in 8-byte
        // units — every non-final piece's payload is unit-aligned by
        // the payload_per_piece mask.
        let field = if more {
            0x2000 | ((offset / 8) as u16)
        } else {
            (offset / 8) as u16
        };
        piece[6..8].copy_from_slice(&field.to_be_bytes());
        // The header changed (length, flags, offset): its checksum is
        // its own again.
        piece[10..12].copy_from_slice(&[0, 0]);
        let sum = checksum::sum_words(&piece[..ihl]);
        let folded = !checksum::fold(sum);
        piece[10..12].copy_from_slice(&folded.to_be_bytes());
        pieces.push(piece);
        offset += take;
        if !more {
            break;
        }
    }
    Some(pieces)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One IPv4 packet with the given DF flag and payload.
    fn v4(df: bool, payload_len: usize) -> Vec<u8> {
        let total = 20 + payload_len;
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0x2211u16.to_be_bytes());
        let field: u16 = if df { 0x4000 } else { 0 };
        packet[6..8].copy_from_slice(&field.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        for (index, byte) in packet[20..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let sum = checksum::sum_words(&packet[..20]);
        let folded = !checksum::fold(sum);
        packet[10..12].copy_from_slice(&folded.to_be_bytes());
        packet
    }

    #[test]
    fn an_oversize_datagram_splits_into_fitting_pieces() {
        let packet = v4(false, 3000);
        let pieces = split(&packet, 1500).expect("three pieces");
        assert_eq!(pieces.len(), 3);
        assert!(pieces.iter().all(|p| p.len() <= 1500));
        // MF set on all but the last; offsets climb in 8-byte units.
        let field = |p: &Vec<u8>| u16::from_be_bytes([p[6], p[7]]);
        assert_eq!(field(&pieces[0]), 0x2000);
        assert_eq!(
            field(&pieces[1]),
            0x2000 | ((pieces[0].len() - 20) / 8) as u16
        );
        assert_eq!(field(&pieces[2]) & 0x2000, 0);
    }

    #[test]
    fn the_pieces_reassemble_into_the_original() {
        let packet = v4(false, 3000);
        let pieces = split(&packet, 1500).expect("pieces");
        // The reassembly arithmetic is the splitter's mirror: stack
        // the payloads back at their offsets.
        let ihl = 20;
        let mut whole = vec![0u8; ihl];
        whole.copy_from_slice(&packet[..ihl]);
        whole.resize(packet.len(), 0);
        for piece in &pieces {
            let field = u16::from_be_bytes([piece[6], piece[7]]);
            let offset = (field & 0x1fff) as usize * 8;
            whole[ihl + offset..ihl + offset + piece.len() - ihl].copy_from_slice(&piece[ihl..]);
        }
        // The header differs only where reassembly fixes it (length,
        // flags): compare the payload and the fixed fields.
        assert_eq!(&whole[ihl..], &packet[ihl..]);
    }

    #[test]
    fn a_fitting_packet_needs_no_split() {
        assert!(split(&v4(false, 100), 1500).is_none());
    }

    #[test]
    fn a_df_datagram_refuses_to_split() {
        assert!(split(&v4(true, 3000), 1500).is_none());
    }

    #[test]
    fn every_piece_carries_a_valid_header_checksum() {
        let pieces = split(&v4(false, 3000), 1500).expect("pieces");
        for piece in pieces {
            let sum = checksum::sum_words(&piece[..20]);
            assert_eq!(checksum::fold(sum), 0xffff, "the folded sum is all ones");
        }
    }
}
