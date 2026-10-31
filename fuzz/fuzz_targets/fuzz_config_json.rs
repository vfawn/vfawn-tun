// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The configuration JSON surface: arbitrary bytes go in, a config or a
//! rejection comes out. Two limits are the assertion, not the
//! assumption: serde's recursion depth must reject bottomless nesting
//! instead of exhausting the stack, and rejection must never be a
//! panic. A config that parses gets its validation run in the same
//! breath, since validation is part of the same hostile input path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vfawn_core::VfawnConfig;

fuzz_target!(|data: &[u8]| {
    if let Ok(config) = serde_json::from_slice::<VfawnConfig>(data) {
        let _ = config.validate();
        // A parsed config must also serialize back without panicking.
        let _ = serde_json::to_string(&config);
    }
});
