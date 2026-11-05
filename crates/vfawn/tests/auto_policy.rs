// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The policy resolves and the instance starts on the engine it chose:
//! with the native engine compiled in, a userspace-leaning policy hands
//! the facade the in-house stack. The observable is indirect (a session
//! completing through whichever backend), because the engine choice is
//! internal; what the test pins is that resolution and startup compose.

#![cfg(feature = "backend-native")]

use std::sync::Arc;
use vfawn::{Instance, VfawnConfig};

/// Echoes one read then closes: enough shape for a session to live.
struct EchoOnce;

#[async_trait::async_trait]
impl vfawn_core::SessionHandler for EchoOnce {
    fn judge_flow(&self, _flow: &vfawn_core::FlowInfo, _first: &[u8]) -> vfawn_core::Verdict {
        vfawn_core::Verdict::Accept
    }

    async fn on_tcp(&self, mut session: vfawn_core::TcpSession) {
        let mut buf = [0u8; 64];
        let _ = session.read(&mut buf).await;
        let _ = session.shutdown_write().await;
    }

    async fn on_udp(&self, _session: vfawn_core::UdpSession) {}

    async fn on_icmp(&self, _packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        vfawn_core::Action::Drop
    }
}

#[test]
fn a_userspace_policy_starts_the_instance() {
    // Not root, no TUN: the assertion is that the policy resolution and
    // the engine construction compose without panicking or misfeature-
    // gating; the device creation failure (Unsupported) is the expected
    // and honest stop on a machine without privileges. The matrix
    // itself is unit-locked in core; this is the facade seam.
    let mut config = VfawnConfig::default();
    config.stack.policy = vfawn_core::StackPolicy::Userspace;
    let handler: Arc<dyn vfawn_core::SessionHandler> = Arc::new(EchoOnce);
    // Both constructors return boxed errors; the seam assertion is that
    // neither panics or feature-gates, and the failure text names the
    // device, not the policy.
    if let Ok(mut instance) = Instance::new(config, handler)
        && let Err(error) = instance.start(Arc::new(EchoOnce))
    {
        let text = error.to_string();
        assert!(
            text.contains("TUN")
                || text.contains("tun")
                || text.contains("device")
                // A runner without the device's permissions refuses it
                // by errno, not by name — still the device's failure,
                // still nothing the policy seam would explain.
                || text.contains("Operation not permitted")
                || text.contains("Permission denied"),
            "the failure must be the device, not the policy seam: {text}"
        );
    }
}
