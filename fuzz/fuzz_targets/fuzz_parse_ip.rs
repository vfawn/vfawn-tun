// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The IPv4 parse family: header, flow identity, fragments. Everything
//! arriving from a device is hostile until parsed; this target holds the
//! line that parsing is an error or a value, never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vfawn_wire::flow::{flow_key, fragment_info};
use vfawn_wire::ipv4::Ipv4Header;

fuzz_target!(|data: &[u8]| {
    if let Ok((header, payload)) = Ipv4Header::parse(data) {
        // A successful parse must round-trick its own invariants: the
        // payload never reaches past the buffer, and the flow identity
        // derives without indexing beyond it.
        let _ = header.header_len;
        let _ = fragment_info(data);
        let _ = flow_key(data);
        let _ = payload;
    }
    let _ = fragment_info(data);
    let _ = flow_key(data);
});
