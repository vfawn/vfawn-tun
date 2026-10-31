// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The UDP header under arbitrary bytes: the length field claims a size
//! that must be checked against the buffer before anything trusts it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vfawn_wire::udp::UdpHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok((header, payload)) = UdpHeader::parse(data) {
        let _ = header.length;
        let _ = payload.len();
    }
});
