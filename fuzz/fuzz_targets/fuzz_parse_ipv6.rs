// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The IPv6 header and its extension-header chain: the chain is a linked
//! list embedded in attacker bytes, and the walk must terminate at a
//! header boundary or an error, never run past the buffer or loop.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vfawn_wire::ipv6::{Ipv6Header, V6Payload};
use vfawn_wire::protocol::IpProtocol;

fuzz_target!(|data: &[u8]| {
    if let Ok((header, payload)) = Ipv6Header::parse(data) {
        let _ = header.payload_len;
        if let Ok(walked) = V6Payload::walk(header.next_header, payload) {
            let _ = walked.protocol;
            let _ = walked.bytes.len();
        }
    }
    // The walk is also reachable with any claimed first protocol.
    if let Ok(walked) = V6Payload::walk(IpProtocol::HopByHop, data) {
        let _ = walked.bytes.len();
    }
});
