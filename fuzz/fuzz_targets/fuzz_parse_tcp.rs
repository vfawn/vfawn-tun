// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The TCP header under arbitrary bytes: the data-offset field is
//! attacker-controlled and checked against the buffer, the flags
//! queries must hold for any combination, and nothing panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vfawn_wire::tcp::{TcpFlags, TcpHeader};

fuzz_target!(|data: &[u8]| {
    if let Ok((header, payload)) = TcpHeader::parse(data) {
        let flags = header.flags;
        let _ = flags.is_syn();
        let _ = flags.is_pure_ack();
        let _ = flags.contains(TcpFlags::RST);
        let _ = header.header_len;
        let _ = payload.len();
    }
});
