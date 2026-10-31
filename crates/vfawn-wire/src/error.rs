// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Parse failures.
//!
//! Everything arriving from a device is hostile input, so every parser in
//! this crate reports problems as values instead of panicking or trusting
//! lengths from the wire.

/// Why a packet could not be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Fewer bytes than the header layout demands.
    Truncated,
    /// The bytes are present but cannot describe a valid header: wrong IP
    /// version, an IHL below the minimum, a length field smaller than the
    /// header itself, and so on.
    Malformed(&'static str),
    /// Structurally valid but not something this parser walks, such as an
    /// IPv6 extension header type outside the minimal set.
    Unsupported(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("packet truncated"),
            Self::Malformed(what) => write!(f, "malformed packet: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported packet: {what}"),
        }
    }
}

impl std::error::Error for ParseError {}
