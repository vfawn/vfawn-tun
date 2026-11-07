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

/// The SYN options this stack reads (RFC 9293 §3.7.1's MSS, RFC 7323
/// §2.2's window scale). Everything else walks past unread.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SynOptions {
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    /// The Timestamps option (RFC 7323 §3.2, kind 8, length 10):
    /// the sender's clock and its echo of ours. None when the peer
    /// did not offer them.
    pub timestamps: Option<Timestamps>,
}

/// The two clock words a Timestamps option carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timestamps {
    /// TSval: the sender's own clock at send time.
    pub tsval: u32,
    /// TSecr: the sender's echo of OUR latest clock, zero when it has
    /// none yet (the SYN itself carries no echo).
    pub tsecr: u32,
}

/// Parse a TCP segment's option region (between the fixed header and
/// the data-offset boundary). A malformed length ends the walk the way
/// a receiving stack would: with what it found so far.
pub fn syn_options(segment: &[u8]) -> SynOptions {
    let mut options = SynOptions::default();
    if segment.len() < MIN_HEADER {
        return options;
    }
    let end = ((segment[12] >> 4) as usize) * 4;
    if end > segment.len() {
        return options;
    }
    let mut at = MIN_HEADER;
    while at + 1 < end {
        match segment[at] {
            0 => break,
            1 => at += 1,
            kind => {
                let Some(len) = segment.get(at + 1).copied() else {
                    break;
                };
                let len = len as usize;
                if len < 2 || at + len > end {
                    break;
                }
                if kind == 2 && len == 4 {
                    options.mss = Some(u16::from_be_bytes([segment[at + 2], segment[at + 3]]));
                } else if kind == 3 && len == 3 {
                    options.wscale = Some(segment[at + 2]);
                } else if kind == 8 && len == 10 && at + 10 <= end {
                    options.timestamps = Some(Timestamps {
                        tsval: u32::from_be_bytes([
                            segment[at + 2],
                            segment[at + 3],
                            segment[at + 4],
                            segment[at + 5],
                        ]),
                        tsecr: u32::from_be_bytes([
                            segment[at + 6],
                            segment[at + 7],
                            segment[at + 8],
                            segment[at + 9],
                        ]),
                    });
                }
                at += len;
            }
        }
    }
    options
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

#[cfg(test)]
mod option_tests {
    use super::*;

    #[test]
    fn syn_options_read_mss_wscale_and_walk_others() {
        let segment = [
            0u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            8 << 4,
            0x02,
            0,
            0,
            0,
            0,
            0,
            0,
            2,
            4,
            0x05,
            0x78, // MSS 1400
            4,
            2, // SACK permitted
            3,
            3,
            7, // window scale 7
            0, // end of list
            1,
            1, // padding
        ];
        let options = syn_options(&segment);
        assert_eq!(options.mss, Some(1400));
        assert_eq!(options.wscale, Some(7));
    }

    #[test]
    fn syn_options_stop_at_malformed_length() {
        let mut segment = [0u8; 24];
        segment[12] = 6 << 4;
        segment[20] = 2;
        segment[21] = 8; // a lying MSS length
        let options = syn_options(&segment);
        assert_eq!(options, SynOptions::default());
    }

    #[test]
    fn syn_options_absent_when_header_is_bare() {
        let mut segment = [0u8; 20];
        segment[12] = 5 << 4;
        assert_eq!(syn_options(&segment), SynOptions::default());
    }
}
