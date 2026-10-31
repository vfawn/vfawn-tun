// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! UDP header (RFC 768).

use crate::error::ParseError;

pub const MIN_HEADER: usize = 8;

/// A parsed UDP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    /// Includes the eight header bytes; checked against the buffer.
    pub length: u16,
    /// Zero means the sender skipped the checksum, which IPv4 permits and
    /// IPv6 does not (there it stands for UDP zero-checksum handling).
    pub checksum: u16,
}

impl UdpHeader {
    /// Parse the header and return it with the datagram payload.
    pub fn parse(buf: &[u8]) -> Result<(UdpHeader, &[u8]), ParseError> {
        if buf.len() < MIN_HEADER {
            return Err(ParseError::Truncated);
        }
        let src_port = u16::from_be_bytes([buf[0], buf[1]]);
        let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
        let length = u16::from_be_bytes([buf[4], buf[5]]);
        let checksum = u16::from_be_bytes([buf[6], buf[7]]);
        if (length as usize) < MIN_HEADER {
            return Err(ParseError::Malformed("length below header size"));
        }
        let end = (length as usize).min(buf.len());
        Ok((
            UdpHeader {
                src_port,
                dst_port,
                length,
                checksum,
            },
            &buf[MIN_HEADER..end],
        ))
    }
}
