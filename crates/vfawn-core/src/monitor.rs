// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Platform event feed.
//!
//! One event enum covers both monitoring abstractions the hosts of
//! comparable stacks are used to: any-change notification and default
//! interface tracking. Implementations live in the platform crate and push
//! into a lossy queue; consumers that need guaranteed delivery snapshot
//! state instead of relying on events.

/// Which termination strategy a flow or instance uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum StackKind {
    Userspace,
    System,
    Mixed,
}

/// A change in the host network environment worth telling the host about.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum MonitorEvent {
    /// Something in the host network configuration changed; details were
    /// folded into this one signal on purpose, since consumers re-query
    /// state anyway.
    NetworkChanged,
    /// The interface owning the default route changed. `None` when the
    /// host lost its default route entirely.
    DefaultInterfaceChanged { name: Option<String> },
    /// The Android VPN toggle flipped.
    AndroidVpnToggled { enabled: bool },
    /// Whether the process currently runs inside a network extension.
    UnderNetworkExtension(bool),
    /// A route reconciliation applied. The summary is a human-readable
    /// description of the operations that ran.
    RouteApplied { summary: String },
    /// A stack backend degraded to another one; `reason` says why.
    StackFallback {
        from: StackKind,
        to: StackKind,
        reason: String,
    },
}
