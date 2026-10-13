// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Session metrics and event export.
//!
//! Counters accumulate here and are exposed through the host-facing API on
//! demand. Storage, aggregation backends and anything downstream of export
//! stay with the host; this crate only observes.
