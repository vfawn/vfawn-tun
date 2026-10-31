// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! ICMPv4 header, minimal surface (RFC 792).
//!
//! The data plane only needs to classify and, for echo traffic, identify
//! the exchange; full parsing belongs to whoever terminates ICMP.

use crate::error::ParseError;

pub const MIN_HEADER: usize = 4;
pub const ECHO_REPLY: u8 = 0;
pub const DESTINATION_UNREACHABLE: u8 = 3;
pub const ECHO_REQUEST: u8 = 8;
pub const TIME_EXCEEDED: u8 = 11;

/// A parsed ICMPv4 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmpv4Header {
    pub kind: u8,
    pub code: u8,
    pub checksum: u16,
}

impl Icmpv4Header {
    /// Parse the fixed four bytes; the rest of the message is returned
    /// untouched for the caller to interpret per type.
    pub fn parse(buf: &[u8]) -> Result<(Icmpv4Header, &[u8]), ParseError> {
        if buf.len() < MIN_HEADER {
            return Err(ParseError::Truncated);
        }
        Ok((
            Icmpv4Header {
                kind: buf[0],
                code: buf[1],
                checksum: u16::from_be_bytes([buf[2], buf[3]]),
            },
            &buf[MIN_HEADER..],
        ))
    }
}
