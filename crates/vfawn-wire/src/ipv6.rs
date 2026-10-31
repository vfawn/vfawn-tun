// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! IPv6 fixed header and the minimal extension-header walk (RFC 8200).
//!
//! Walking means skipping: hop-by-hop, routing and destination options
//! carry nothing the data plane needs, and their length units are octets in
//! multiples of eight, not counting the first eight (RFC 8200 §4.2). The
//! Authentication Header counts in multiples of four instead
//! (RFC 4302 §2.2). Fragmentation gets special treatment because only the
//! first fragment of a datagram carries the transport header, which is
//! exactly what flow hashing needs to know.

use crate::error::ParseError;
use crate::protocol::IpProtocol;
use std::net::Ipv6Addr;

pub const MIN_HEADER: usize = 40;
const VERSION: u8 = 6;

/// The fixed IPv6 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header {
    /// Traffic class and flow label as carried on the wire.
    pub traffic_class_flow: u32,
    pub payload_len: u16,
    pub next_header: IpProtocol,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

/// What an extension-header walk found at the end of the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V6Payload<'a> {
    /// The first header after the chain that is not an extension header.
    pub protocol: IpProtocol,
    /// The bytes after the chain. Empty for later fragments, which carry no
    /// transport header at all.
    pub bytes: &'a [u8],
    /// Present when a fragment header appeared in the chain.
    pub fragment: Option<FragmentInfoV6>,
}

/// Fragment bookkeeping from the fragment header (RFC 8200 §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentInfoV6 {
    pub identification: u32,
    /// Offset in 8-octet units; zero means this is the first fragment.
    pub offset: u16,
    pub more: bool,
}

impl Ipv6Header {
    /// Parse the fixed header and return it with everything after it.
    pub fn parse(buf: &[u8]) -> Result<(Ipv6Header, &[u8]), ParseError> {
        if buf.len() < MIN_HEADER {
            return Err(ParseError::Truncated);
        }
        let version = buf[0] >> 4;
        if version != VERSION {
            return Err(ParseError::Malformed("not IPv6"));
        }
        let traffic_class_flow = u32::from_be_bytes([buf[0] & 0x0f, buf[1], buf[2], buf[3]]);
        let payload_len = u16::from_be_bytes([buf[4], buf[5]]);
        let next_header = IpProtocol::from_number(buf[6]);
        let hop_limit = buf[7];
        let mut src = [0u8; 16];
        src.copy_from_slice(&buf[8..24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&buf[24..40]);
        Ok((
            Ipv6Header {
                traffic_class_flow,
                payload_len,
                next_header,
                hop_limit,
                src: Ipv6Addr::from(src),
                dst: Ipv6Addr::from(dst),
            },
            &buf[MIN_HEADER..],
        ))
    }
}

impl<'a> V6Payload<'a> {
    /// Walk the extension-header chain starting at `first` inside `bytes`.
    ///
    /// Stops at the first header that is not an extension header. A
    /// fragment header with a nonzero offset ends the walk with an empty
    /// payload, since later fragments hold no transport header.
    pub fn walk(first: IpProtocol, mut bytes: &'a [u8]) -> Result<V6Payload<'a>, ParseError> {
        let mut next = first;
        let mut fragment = None;
        loop {
            match next {
                IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::DestOpts => {
                    if bytes.len() < 2 {
                        return Err(ParseError::Truncated);
                    }
                    let len = bytes[1] as usize * 8 + 8;
                    if bytes.len() < len {
                        return Err(ParseError::Truncated);
                    }
                    next = IpProtocol::from_number(bytes[0]);
                    bytes = &bytes[len..];
                }
                IpProtocol::FragmentHeader => {
                    if bytes.len() < 8 {
                        return Err(ParseError::Truncated);
                    }
                    let after = IpProtocol::from_number(bytes[0]);
                    let offset_and_more = u16::from_be_bytes([bytes[2], bytes[3]]);
                    fragment = Some(FragmentInfoV6 {
                        identification: u32::from_be_bytes([
                            bytes[4], bytes[5], bytes[6], bytes[7],
                        ]),
                        offset: offset_and_more >> 3,
                        more: offset_and_more & 1 != 0,
                    });
                    if offset_and_more >> 3 != 0 {
                        // Later fragment: nothing parseable follows.
                        return Ok(V6Payload {
                            protocol: after,
                            bytes: &[],
                            fragment,
                        });
                    }
                    next = after;
                    bytes = &bytes[8..];
                }
                IpProtocol::Ah => {
                    if bytes.len() < 2 {
                        return Err(ParseError::Truncated);
                    }
                    let len = bytes[1] as usize * 4 + 8;
                    if bytes.len() < len {
                        return Err(ParseError::Truncated);
                    }
                    next = IpProtocol::from_number(bytes[0]);
                    bytes = &bytes[len..];
                }
                IpProtocol::NoNextHeader => {
                    return Ok(V6Payload {
                        protocol: next,
                        bytes,
                        fragment,
                    });
                }
                transport => {
                    return Ok(V6Payload {
                        protocol: transport,
                        bytes,
                        fragment,
                    });
                }
            }
        }
    }
}
