// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Behavior shared across Unix targets: adopted-fd handling for hosts that
//! supply the device (VPN services, network extensions) and interface-bound
//! sockets for the anti-loopback path.
