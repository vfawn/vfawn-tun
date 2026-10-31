// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! TCP header (RFC 9293 §3.1).

use crate::error::ParseError;

pub const MIN_HEADER: usize = 20;

/// The nine defined control bits, in wire order (RFC 9293 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: TcpFlags = TcpFlags(0x01);
    pub const SYN: TcpFlags = TcpFlags(0x02);
    pub const RST: TcpFlags = TcpFlags(0x04);
    pub const PSH: TcpFlags = TcpFlags(0x08);
    pub const ACK: TcpFlags = TcpFlags(0x10);
    pub const URG: TcpFlags = TcpFlags(0x20);
    pub const ECE: TcpFlags = TcpFlags(0x40);
    pub const CWR: TcpFlags = TcpFlags(0x80);

    pub fn from_bits(bits: u8) -> Self {
        TcpFlags(bits)
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, other: TcpFlags) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn union(self, other: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 | other.0)
    }

    pub fn is_syn(self) -> bool {
        self.contains(Self::SYN) && !self.contains(Self::ACK)
    }

    pub fn is_pure_ack(self) -> bool {
        self.contains(Self::ACK) && !self.contains(Self::SYN) && !self.contains(Self::RST)
    }
}

/// A parsed TCP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    /// Header length in bytes, data-offset times four; options included.
    pub header_len: usize,
}

impl TcpHeader {
    /// Parse the header and return it with the segment payload.
    ///
    /// The data-offset field is checked against the buffer, and the
    /// returned slice stops where the data-offset says the options end.
    pub fn parse(buf: &[u8]) -> Result<(TcpHeader, &[u8]), ParseError> {
        if buf.len() < MIN_HEADER {
            return Err(ParseError::Truncated);
        }
        let src_port = u16::from_be_bytes([buf[0], buf[1]]);
        let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
        let seq = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ack = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let data_offset = (buf[12] >> 4) as usize;
        if data_offset < 5 {
            return Err(ParseError::Malformed("data offset below minimum"));
        }
        let header_len = data_offset * 4;
        if buf.len() < header_len {
            return Err(ParseError::Truncated);
        }
        let flags = TcpFlags::from_bits(buf[13]);
        let window = u16::from_be_bytes([buf[14], buf[15]]);
        let checksum = u16::from_be_bytes([buf[16], buf[17]]);
        let urgent_ptr = u16::from_be_bytes([buf[18], buf[19]]);
        Ok((
            TcpHeader {
                src_port,
                dst_port,
                seq,
                ack,
                flags,
                window,
                checksum,
                urgent_ptr,
                header_len,
            },
            &buf[header_len..],
        ))
    }
}
