// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The Auto policy's decision: which termination engine a captured flow
//! rides, chosen from platform and device facts before the first
//! packet. Pure logic, no I/O ,  every input is a fact the caller
//! already holds, so the whole matrix is table-testable and the
//! deployment behavior is exactly what the tests assert.
//!
//! The reasoning is one paragraph: the kernel stack is the maturity
//! bench every platform tunes for, so wherever the kernel can own the
//! flow it does; the userspace stacks exist for the traffic the kernel
//! path cannot carry ,  full-capture modes where every byte must pass
//! the host's judgment, and platforms whose kernel offers no
//! programmable path at all. Offload changes nothing here yet (the
//! userspace engines are batch-capable in design but vnet headers are
//! parked on evidence); it enters the matrix the day that flips.

use crate::StackPolicy;

/// The facts Auto decides on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoFacts {
    /// The platform the instance runs on.
    pub platform: Platform,
    /// Full-capture semantics: every flow, including the host's own
    /// outbound, must terminate in userspace.
    pub include_all_networks: bool,
    /// Whether a programmable kernel termination path exists here.
    pub kernel_path_available: bool,
}

/// The platforms with distinct truths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Darwin,
    Windows,
    Android,
}

/// What Auto decided for a flow family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoChoice {
    /// The kernel's termination path (system stack).
    Kernel,
    /// The in-house userspace stack.
    Userspace,
}

impl StackPolicy {
    /// Resolve Auto (and the trivial policies) to a choice under the
    /// given facts. Explicit policies answer themselves; only Auto
    /// consults the matrix.
    pub fn resolve(&self, facts: &AutoFacts) -> AutoChoice {
        match self {
            StackPolicy::Userspace => AutoChoice::Userspace,
            StackPolicy::System | StackPolicy::ByRule { .. } => AutoChoice::Kernel,
            StackPolicy::Auto => auto_decide(facts),
        }
    }
}

/// The matrix itself: full capture outranks everything (a kernel path
/// that lets some traffic escape is not the configured product); no
/// kernel path leaves userspace as the only option; otherwise the
/// kernel owns Linux's bulk (its TCP corners are the mature ones) and
/// the BSD-lineage and Windows kernels do the same for their own
/// platforms, leaving userspace to prove itself where it already has
/// (Android ships no programmable kernel termination in practice).
pub fn auto_decide(facts: &AutoFacts) -> AutoChoice {
    if facts.include_all_networks {
        return AutoChoice::Userspace;
    }
    if !facts.kernel_path_available {
        return AutoChoice::Userspace;
    }
    match facts.platform {
        Platform::Linux | Platform::Darwin | Platform::Windows => AutoChoice::Kernel,
        Platform::Android => AutoChoice::Userspace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(platform: Platform, full: bool, kernel: bool) -> AutoFacts {
        AutoFacts {
            platform,
            include_all_networks: full,
            kernel_path_available: kernel,
        }
    }

    #[test]
    fn full_capture_overrides_everything() {
        for platform in [
            Platform::Linux,
            Platform::Darwin,
            Platform::Windows,
            Platform::Android,
        ] {
            assert_eq!(
                auto_decide(&facts(platform, true, true)),
                AutoChoice::Userspace,
                "{platform:?}: every byte must pass the host"
            );
        }
    }

    #[test]
    fn no_kernel_path_leaves_userspace() {
        assert_eq!(
            auto_decide(&facts(Platform::Linux, false, false)),
            AutoChoice::Userspace
        );
    }

    #[test]
    fn linux_bulk_rides_the_kernel() {
        assert_eq!(
            auto_decide(&facts(Platform::Linux, false, true)),
            AutoChoice::Kernel
        );
    }

    #[test]
    fn explicit_policies_answer_themselves() {
        let any = facts(Platform::Linux, true, true);
        assert_eq!(StackPolicy::Userspace.resolve(&any), AutoChoice::Userspace);
        assert_eq!(StackPolicy::System.resolve(&any), AutoChoice::Kernel);
    }

    #[test]
    fn android_full_capture_doubles_down_on_userspace() {
        assert_eq!(
            auto_decide(&facts(Platform::Android, false, false)),
            AutoChoice::Userspace
        );
    }
}
