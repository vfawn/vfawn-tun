// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! IPv4 header (RFC 791).
//!
//! The parser trusts nothing: the version and IHL are checked against the
//! layout, the total-length field is checked against the buffer, and the
//! payload handed back is bounded by both.

use crate::error::ParseError;
use crate::protocol::IpProtocol;
use std::net::Ipv4Addr;

pub const MIN_HEADER: usize = 20;
const VERSION: u8 = 4;
const MORE_FRAGMENTS: u16 = 0x2000;
const OFFSET_MASK: u16 = 0x1fff;

/// A parsed IPv4 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    pub dscp_ecn: u8,
    pub total_len: u16,
    pub identification: u16,
    /// Fragment offset in 8-octet units (RFC 791 §3.1, flags-and-fragment
    /// field low 13 bits).
    pub fragment_offset: u16,
    /// The More Fragments flag; first fragments have it set with a zero
    /// offset, later fragments have a nonzero offset.
    pub more_fragments: bool,
    pub dont_fragment: bool,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub header_checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    /// Header length in bytes, IHL times four; options included.
    pub header_len: usize,
}

impl Ipv4Header {
    /// Parse the header and return it together with the payload slice.
    ///
    /// The payload is bounded by the minimum of what the buffer holds and
    /// what the total-length field claims, since either can lie: a short
    /// buffer means Ethernet padding was not the only trimming, and an
    /// overlong total-length field would read past the packet.
    pub fn parse(buf: &[u8]) -> Result<(Ipv4Header, &[u8]), ParseError> {
        if buf.len() < MIN_HEADER {
            return Err(ParseError::Truncated);
        }
        let version = buf[0] >> 4;
        if version != VERSION {
            return Err(ParseError::Malformed("not IPv4"));
        }
        let ihl = (buf[0] & 0x0f) as usize;
        if ihl < 5 {
            return Err(ParseError::Malformed("IHL below minimum"));
        }
        let header_len = ihl * 4;
        if buf.len() < header_len {
            return Err(ParseError::Truncated);
        }
        let dscp_ecn = buf[1];
        let total_len = u16::from_be_bytes([buf[2], buf[3]]);
        if (total_len as usize) < header_len {
            return Err(ParseError::Malformed("total length below header length"));
        }
        let identification = u16::from_be_bytes([buf[4], buf[5]]);
        let flags_and_fragment = u16::from_be_bytes([buf[6], buf[7]]);
        let fragment_offset = flags_and_fragment & OFFSET_MASK;
        let more_fragments = flags_and_fragment & MORE_FRAGMENTS != 0;
        let dont_fragment = flags_and_fragment & 0x4000 != 0;
        let ttl = buf[8];
        let protocol = IpProtocol::from_number(buf[9]);
        let header_checksum = u16::from_be_bytes([buf[10], buf[11]]);
        let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
        let end = (total_len as usize).min(buf.len());
        Ok((
            Ipv4Header {
                dscp_ecn,
                total_len,
                identification,
                fragment_offset,
                more_fragments,
                dont_fragment,
                ttl,
                protocol,
                header_checksum,
                src,
                dst,
                header_len,
            },
            &buf[header_len..end],
        ))
    }

    /// Verify the header checksum over the raw bytes it was parsed from.
    pub fn verify_checksum(raw: &[u8]) -> bool {
        let header_len = ((raw[0] & 0x0f) as usize) * 4;
        if raw.len() < header_len {
            return false;
        }
        crate::checksum::checksum(&raw[..header_len]) == 0
    }
}
