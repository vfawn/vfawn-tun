// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Packet-level primitives shared by every layer that must look inside a
//! packet.
//!
//! Header parsers and checksums are used from three directions at once: the
//! dispatcher (flow keys, DNS rewrite), the kernel NAT path (address rewrite
//! on the TUN write-back), and the user-space stack itself. Keeping them in
//! one zero-dependency crate means none of those layers has to depend on any
//! other.
//!
//! Parsers are strict by construction: malformed input is returned as an
//! error, never a panic. Everything arriving from a TUN device is untrusted
//! input, and parse paths must be safe to fuzz with arbitrary bytes.
