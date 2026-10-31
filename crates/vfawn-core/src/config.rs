// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Host-facing configuration model.
//!
//! Five sections, constructed once and applied atomically. Every field has
//! a default so a minimal JSON document is a valid configuration. The
//! structures are strict on input: unknown fields are rejected, and
//! [`VfawnConfig::validate`] enforces size bounds so a hostile document
//! cannot ask for unbounded kernel state or unbounded memory.

use crate::monitor::StackKind;
use crate::session::Network;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Duration;

/// Upper bounds a configuration document must respect. Hostile input is
/// rejected at parse and validate time rather than triggering large
/// allocations downstream.
pub mod limits {
    /// Longest interface name the kernel accepts (IFNAMSIZ minus one).
    pub const IFACE_NAME: usize = 15;
    /// Longest process or package selector.
    pub const PROCESS_NAME: usize = 256;
    /// Longest single address list.
    pub const ADDRESSES: usize = 64;
    /// Longest route or exclusion list.
    pub const PREFIXES: usize = 4096;
    /// Longest interface selector list.
    pub const INTERFACES: usize = 64;
    /// Longest uid range list.
    pub const UID_RANGES: usize = 256;
    /// Longest per-flow stack rule list.
    pub const STACK_RULES: usize = 1024;
    /// Smallest MTU the IPv4 path can carry.
    pub const MTU_MIN: u32 = 68;
    /// Largest MTU any TUN device in practice carries.
    pub const MTU_MAX: u32 = 65535;
}

/// How the device should treat packet offload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OffloadPolicy {
    /// Use it when the device reports support.
    #[default]
    Auto,
    On,
    Off,
}

/// How many device queues to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum QueuePolicy {
    /// One queue per CPU, capped by device support.
    #[default]
    Auto,
    /// An exact queue count.
    Fixed {
        queues: usize,
    },
    Off,
}

/// Device creation and framing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceConfig {
    /// Interface name; derived per platform when absent.
    pub name: Option<String>,
    /// Zero means pick per platform: roughly 4064 inside network
    /// extensions, 9000 on Android, 65535 elsewhere. Offload favors the
    /// larger values, since bigger frames mean fewer syscalls.
    #[serde(default)]
    pub mtu: u32,
    pub inet4_address: Vec<Ipv4Net>,
    pub inet6_address: Vec<Ipv6Net>,
    /// Derived per platform when absent (next address on Linux, own
    /// address on Darwin).
    pub inet4_gateway: Option<Ipv4Addr>,
    pub inet6_gateway: Option<Ipv6Addr>,
    /// Adopt an fd supplied by the host (VPN service, network extension).
    /// The fd must be framed without packet information and without vnet
    /// headers; an adopted fd has no offload by nature.
    pub file_descriptor: Option<RawFd>,
    pub offload: OffloadPolicy,
    pub multi_queue: QueuePolicy,
}

/// Which traffic the instance captures, and what it never touches.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteConfig {
    /// Take over routing at all. Off by default: an explicit opt-in is the
    /// safer posture for something that edits kernel state.
    pub auto_route: bool,
    /// Harden against leaks: block protocol families that are not
    /// captured, pin DNS toward the captured path.
    pub strict_route: bool,
    /// Captured prefixes; empty with `auto_route` means the default route.
    pub route_address: Vec<IpNet>,
    pub route_exclude_address: Vec<IpNet>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<RangeInclusive<u32>>,
    pub exclude_uid: Vec<RangeInclusive<u32>>,
    /// Android user ids and package selectors, honored on Android only.
    pub include_android_user: Vec<i32>,
    pub include_package: Vec<String>,
    pub exclude_package: Vec<String>,
    /// Dedicated routing table and rule base index.
    pub table_index: u32,
    pub rule_index: u32,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            auto_route: false,
            strict_route: false,
            route_address: Vec::new(),
            route_exclude_address: Vec::new(),
            include_interface: Vec::new(),
            exclude_interface: Vec::new(),
            include_uid: Vec::new(),
            exclude_uid: Vec::new(),
            include_android_user: Vec::new(),
            include_package: Vec::new(),
            exclude_package: Vec::new(),
            table_index: 2022,
            rule_index: 9000,
        }
    }
}

/// DNS interception mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsMode {
    /// Do not touch interface DNS and do not intercept.
    Disabled,
    /// Set interface DNS without interception.
    Native,
    /// Rewrite port-53 flows toward the virtual resolver addresses.
    #[default]
    Hijack,
}

/// DNS handling.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub mode: DnsMode,
    /// Virtual resolver addresses; derived from the interface prefixes
    /// when empty. DoT and DoH flows are not covered by hijack mode; hosts
    /// that need that enforced must filter those ports themselves.
    pub address: Vec<IpAddr>,
}

/// UDP NAT behavior for address preservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpSessionMode {
    /// One mapping per five-tuple.
    #[default]
    Symmetric,
    /// One mapping per internal endpoint, shared across remotes; what
    /// peer-to-peer and voice flows need.
    EndpointIndependent,
}

/// UDP NAT semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UdpNatConfig {
    pub mode: UdpSessionMode,
    /// NAT table capacity; zero selects a built-in default. When full, the
    /// oldest idle mapping is evicted rather than refusing new flows.
    pub max_entries: u32,
}

/// Congestion control for the user-space stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CongestionAlgo {
    #[default]
    Cubic,
    Bbr,
    Reno,
}

/// Anti-loopback policy for host-created sockets.
///
/// The library does not dial out under the user-space stack; this hook
/// exists so sockets the host opens, and any future library-side fd, do not
/// get captured back into the device.
#[derive(Clone, Default)]
pub enum OutboundFdHook {
    /// Nothing; fine when nothing but the captured path routes into the
    /// device.
    #[default]
    None,
    /// Bind sockets to the current default interface (SO_BINDTODEVICE on
    /// Linux).
    BindDefaultIface,
    /// Hand each fd to the host (Android VPN service protect, or any
    /// custom policy). The callback must be cheap and non-blocking.
    HostCallback(Arc<dyn Fn(RawFd) -> io::Result<()> + Send + Sync>),
}

impl std::fmt::Debug for OutboundFdHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::BindDefaultIface => f.write_str("BindDefaultIface"),
            Self::HostCallback(_) => f.write_str("HostCallback(..)"),
        }
    }
}

// Callbacks cannot travel through a JSON document: hosts that configure
// through the ABI pass their policy in the handler vtable instead, so the
// serialized form carries only the intent and deserialization lands on the
// passive variants.
impl Serialize for OutboundFdHook {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::None => "none",
            Self::BindDefaultIface => "bind-default-iface",
            Self::HostCallback(_) => "host-callback",
        })
    }
}

impl<'de> Deserialize<'de> for OutboundFdHook {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tag = String::deserialize(deserializer)?;
        match tag.as_str() {
            "none" => Ok(Self::None),
            "bind-default-iface" => Ok(Self::BindDefaultIface),
            "host-callback" => Ok(Self::None),
            _ => Err(serde::de::Error::unknown_variant(
                &tag,
                &["none", "bind-default-iface", "host-callback"],
            )),
        }
    }
}

/// One per-flow stack selection rule; first match wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteRule {
    pub network: Option<IpNet>,
    pub protocol: Option<Network>,
    pub port: Option<u16>,
    /// Process identity where the platform can supply one; on Android this
    /// is the package name.
    pub process: Option<String>,
    pub stack: StackKind,
}

impl Default for RouteRule {
    fn default() -> Self {
        Self {
            network: None,
            protocol: None,
            port: None,
            process: None,
            stack: StackKind::Userspace,
        }
    }
}

/// Which termination strategy handles traffic.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StackPolicy {
    Userspace,
    System,
    /// Evaluate the rules in order and terminate each flow on the stack
    /// its first matching rule selects.
    ByRule {
        rules: Vec<RouteRule>,
    },
    /// Pick per platform and device facts; on Linux the kernel path gets
    /// the bulk of the traffic, since the kernel owns the trickier TCP
    /// corners.
    #[default]
    Auto,
}

/// Termination behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StackConfig {
    pub policy: StackPolicy,
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout: Duration,
    #[serde(default = "default_icmp_timeout")]
    pub icmp_timeout: Duration,
    pub udp_nat: UdpNatConfig,
    pub congestion: CongestionAlgo,
    pub outbound_fd_hook: OutboundFdHook,
    /// Full-capture semantics on Darwin; also decides what the automatic
    /// policy leans on.
    pub include_all_networks: bool,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            policy: StackPolicy::default(),
            udp_timeout: default_udp_timeout(),
            icmp_timeout: default_icmp_timeout(),
            udp_nat: UdpNatConfig::default(),
            congestion: CongestionAlgo::default(),
            outbound_fd_hook: OutboundFdHook::default(),
            include_all_networks: false,
        }
    }
}

fn default_udp_timeout() -> Duration {
    Duration::from_secs(5 * 60)
}

fn default_icmp_timeout() -> Duration {
    Duration::from_secs(30)
}

/// Platform-specific knobs. Kept as its own section so per-platform growth
/// does not churn the other four.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformConfig {}

/// The whole configuration of one instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VfawnConfig {
    pub device: DeviceConfig,
    pub route: RouteConfig,
    pub dns: DnsConfig,
    pub stack: StackConfig,
    pub platform: PlatformConfig,
}

/// A configuration was rejected before it could take effect.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    TooMany {
        what: &'static str,
        count: usize,
        max: usize,
    },
    TooLong {
        what: &'static str,
        len: usize,
        max: usize,
    },
    OutOfRange {
        what: &'static str,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooMany { what, count, max } => {
                write!(f, "too many {what}: {count} exceeds {max}")
            }
            Self::TooLong { what, len, max } => {
                write!(f, "{what} too long: {len} exceeds {max}")
            }
            Self::OutOfRange { what } => write!(f, "{what} out of range"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl VfawnConfig {
    /// Check every bounded dimension. Runs after parsing and before any
    /// kernel state is touched, so a hostile document fails here and only
    /// here.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let d = &self.device;
        if d.mtu != 0 && !(limits::MTU_MIN..=limits::MTU_MAX).contains(&d.mtu) {
            return Err(ConfigError::OutOfRange { what: "mtu" });
        }
        check_len("device name", d.name.as_deref(), limits::IFACE_NAME)?;
        check_count("inet4 addresses", d.inet4_address.len(), limits::ADDRESSES)?;
        check_count("inet6 addresses", d.inet6_address.len(), limits::ADDRESSES)?;

        let r = &self.route;
        check_count("route prefixes", r.route_address.len(), limits::PREFIXES)?;
        check_count(
            "excluded prefixes",
            r.route_exclude_address.len(),
            limits::PREFIXES,
        )?;
        check_count(
            "included interfaces",
            r.include_interface.len(),
            limits::INTERFACES,
        )?;
        check_count(
            "excluded interfaces",
            r.exclude_interface.len(),
            limits::INTERFACES,
        )?;
        check_count("uid ranges", r.include_uid.len(), limits::UID_RANGES)?;
        check_count("uid ranges", r.exclude_uid.len(), limits::UID_RANGES)?;
        for name in r.include_interface.iter().chain(&r.exclude_interface) {
            check_len("interface name", Some(name), limits::IFACE_NAME)?;
        }
        for pkg in r.include_package.iter().chain(&r.exclude_package) {
            check_len("package name", Some(pkg), limits::PROCESS_NAME)?;
        }
        if r.table_index == 0 {
            return Err(ConfigError::OutOfRange {
                what: "table_index",
            });
        }

        check_count("dns addresses", self.dns.address.len(), limits::ADDRESSES)?;

        if let StackPolicy::ByRule { rules } = &self.stack.policy {
            check_count("stack rules", rules.len(), limits::STACK_RULES)?;
            for rule in rules {
                check_len(
                    "process name",
                    rule.process.as_deref(),
                    limits::PROCESS_NAME,
                )?;
            }
        }

        Ok(())
    }
}

fn check_count(what: &'static str, count: usize, max: usize) -> Result<(), ConfigError> {
    if count > max {
        return Err(ConfigError::TooMany { what, count, max });
    }
    Ok(())
}

fn check_len(what: &'static str, value: Option<&str>, max: usize) -> Result<(), ConfigError> {
    if let Some(value) = value
        && value.len() > max
    {
        return Err(ConfigError::TooLong {
            what,
            len: value.len(),
            max,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_reference_values() {
        let cfg = VfawnConfig::default();
        assert_eq!(cfg.route.table_index, 2022);
        assert_eq!(cfg.route.rule_index, 9000);
        assert!(!cfg.route.auto_route);
        assert_eq!(cfg.dns.mode, DnsMode::Hijack);
        assert_eq!(cfg.stack.udp_timeout, Duration::from_secs(300));
        assert_eq!(cfg.stack.icmp_timeout, Duration::from_secs(30));
        assert_eq!(cfg.stack.congestion, CongestionAlgo::Cubic);
        assert_eq!(cfg.stack.udp_nat.mode, UdpSessionMode::Symmetric);
        assert_eq!(cfg.device.mtu, 0);
        assert_eq!(cfg.device.offload, OffloadPolicy::Auto);
    }

    #[test]
    fn json_round_trip_keeps_meaningful_fields() {
        let json = r#"{
            "device": {"mtu": 9000, "offload": "on", "multi_queue": {"kind": "fixed", "queues": 4}},
            "route": {"auto_route": true, "table_index": 3000},
            "dns": {"mode": "native"},
            "stack": {"congestion": "bbr", "policy": {"kind": "by-rule", "rules": [
                {"network": "10.0.0.0/8", "stack": "system"}
            ]}}
        }"#;
        let cfg: VfawnConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.device.mtu, 9000);
        assert!(cfg.route.auto_route);
        assert_eq!(cfg.route.table_index, 3000);
        assert_eq!(cfg.dns.mode, DnsMode::Native);
        assert_eq!(cfg.stack.congestion, CongestionAlgo::Bbr);
        match &cfg.stack.policy {
            StackPolicy::ByRule { rules } => assert_eq!(rules.len(), 1),
            other => panic!("unexpected policy {other:?}"),
        }
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = r#"{"device": {"mtu": 1500, "gso": true}}"#;
        assert!(serde_json::from_str::<VfawnConfig>(json).is_err());
    }

    #[test]
    fn oversize_input_is_rejected_by_validate() {
        let mut cfg = VfawnConfig::default();
        cfg.device.name = Some("x".repeat(64));
        assert!(matches!(cfg.validate(), Err(ConfigError::TooLong { .. })));

        let mut cfg = VfawnConfig::default();
        cfg.route.route_address = vec!["10.0.0.0/8".parse().unwrap(); limits::PREFIXES + 1];
        assert!(matches!(cfg.validate(), Err(ConfigError::TooMany { .. })));

        let mut cfg = VfawnConfig::default();
        cfg.device.mtu = 4;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::OutOfRange { .. })
        ));
    }
    #[test]
    fn hook_serializes_as_intent_only() {
        let mut cfg = VfawnConfig::default();
        cfg.stack.outbound_fd_hook = OutboundFdHook::BindDefaultIface;
        let text = serde_json::to_string(&cfg).unwrap();
        assert!(text.contains("bind-default-iface"));
        let back: VfawnConfig = serde_json::from_str(&text).unwrap();
        assert!(matches!(
            back.stack.outbound_fd_hook,
            OutboundFdHook::BindDefaultIface
        ));
    }
}
