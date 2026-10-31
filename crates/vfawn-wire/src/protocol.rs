// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Protocol numbers.
//!
//! The IPv4 protocol field and the IPv6 next-header field share one number
//! space (IANA "Assigned Internet Protocol Numbers"); the transport
//! protocols and the IPv6 extension header types live in the same enum so
//! extension chains can be walked without conversion.

/// An IP protocol or IPv6 next-header value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IpProtocol {
    HopByHop,
    Icmp,
    Tcp,
    Udp,
    Ipv6Route,
    FragmentHeader,
    Ah,
    Icmpv6,
    NoNextHeader,
    DestOpts,
    Other(u8),
}

impl IpProtocol {
    /// The IANA number for this value.
    pub fn number(self) -> u8 {
        match self {
            Self::HopByHop => 0,
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Ipv6Route => 43,
            Self::FragmentHeader => 44,
            Self::Ah => 51,
            Self::Icmpv6 => 58,
            Self::NoNextHeader => 59,
            Self::DestOpts => 60,
            Self::Other(n) => n,
        }
    }

    /// Interpret an IANA number.
    pub fn from_number(number: u8) -> Self {
        match number {
            0 => Self::HopByHop,
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            43 => Self::Ipv6Route,
            44 => Self::FragmentHeader,
            51 => Self::Ah,
            58 => Self::Icmpv6,
            59 => Self::NoNextHeader,
            60 => Self::DestOpts,
            other => Self::Other(other),
        }
    }
}
