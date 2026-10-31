// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Internet checksum (RFC 1071) and the pseudo-header sum used by TCP, UDP
//! and ICMPv6 (RFC 793 §3.1, RFC 768, RFC 8200 §8.1).
//!
//! All functions accumulate a ones' complement sum in host order and return
//! the folded complement, in host order; callers compare against the wire
//! value in whatever byte order keeps the arithmetic honest.

use crate::protocol::IpProtocol;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Sum 16-bit words of `data` in network byte order, padding an odd final
/// byte with zero, and return the complement of the folded sum.
pub fn checksum(data: &[u8]) -> u16 {
    // The complement belongs to the folded sum: complementing before the
    // fold is not the same function, and picking the wrong one yields
    // checksums that verify only by accident.
    !fold(sum_words(data))
}

/// The partial sum of `data` without complement or folding, so callers can
/// chain segments (pseudo-header, then header, then payload).
pub fn sum_words(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut index = 0;
    while index + 1 < data.len() {
        sum += u16::from_be_bytes([data[index], data[index + 1]]) as u32;
        index += 2;
    }
    if index < data.len() {
        // A trailing odd byte counts as the high octet of a final word,
        // which is the padding the receiver applies as well.
        sum += (data[index] as u32) << 8;
    }
    sum
}

/// Fold a 32-bit ones' complement accumulator into 16 bits.
pub fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// The pseudo-header sum for an IPv4 payload: source, destination, zero,
/// protocol, and upper-layer length (RFC 793 §3.1).
pub fn pseudo_header_v4(src: Ipv4Addr, dst: Ipv4Addr, protocol: IpProtocol, length: u32) -> u32 {
    let mut sum = 0u32;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += protocol.number() as u32;
    sum += length;
    sum
}

/// The pseudo-header sum for an IPv6 payload: source, destination,
/// upper-layer length as 32 bits, three zero octets, next header
/// (RFC 8200 §8.1).
pub fn pseudo_header_v6(src: Ipv6Addr, dst: Ipv6Addr, protocol: IpProtocol, length: u32) -> u32 {
    let mut sum = 0u32;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += length;
    sum += protocol.number() as u32;
    sum
}

/// Verify a TCP or UDP checksum over the given segment (header plus
/// payload, checksum field included) for IPv4. A correct segment folds to
/// the all-ones sum, so no claimed value needs passing in.
pub fn verify_transport_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: IpProtocol,
    segment: &[u8],
) -> bool {
    let sum = pseudo_header_v4(src, dst, protocol, segment.len() as u32) + sum_words(segment);
    fold(sum) == 0xffff
}

/// Adjust a checksum for one rewritten field, without recomputing the
/// whole sum: RFC 1624's incremental update, `HC' = ~(~HC + m + ~m')`,
/// generalized to a field of any even length.
///
/// This is the surgery a destination rewrite needs: the rest of the
/// packet already contributed its words to the old checksum, so only
/// the replaced field's delta has to be applied. A zero fold becomes
/// `0xffff`, the encoding a receiver expects; UDP callers that must
/// preserve an absent checksum skip the call instead.
pub fn adjust(checksum: u16, old_field: &[u8], new_field: &[u8]) -> u16 {
    debug_assert_eq!(old_field.len(), new_field.len());
    let delta_old = fold(sum_words(old_field)) as u32;
    let delta_new = fold(sum_words(new_field)) as u32;
    // Ones-complement arithmetic in a 32-bit accumulator: one extra
    // 0xffff before the subtraction keeps the value positive, and the
    // two zero representations collapse inside the fold.
    let sum = (!checksum) as u32 + 0xffff - delta_old + delta_new;
    let folded = fold(sum);
    if folded == 0 { 0xffff } else { !folded }
}

/// Verify a TCP or UDP checksum over the given segment for IPv6.
pub fn verify_transport_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    protocol: IpProtocol,
    segment: &[u8],
) -> bool {
    let sum = pseudo_header_v6(src, dst, protocol, segment.len() as u32) + sum_words(segment);
    fold(sum) == 0xffff
}
