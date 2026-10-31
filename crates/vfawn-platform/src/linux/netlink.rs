// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Linux rtnetlink backend for the route engine.
//!
//! The rtnetlink crate uses a type-state builder: `.v4()` / `.v6()` fix
//! the IP version at the type level before chaining destination, table,
//! and interface parameters. A dedicated tokio runtime lives inside this
//! struct and services each sync call with `block_on`.

use futures::TryStreamExt;
use ipnet::IpNet;
use std::io;
use std::net::IpAddr;
use vfawn_route::{
    InterfaceAddress, ObservedState, PolicyRule, RouteBackend, RouteEntry, RouteOp, RuleAction,
    RuleSelector,
};

use netlink_packet_route::{
    AddressFamily,
    address::{AddressAttribute, AddressMessage},
    route::{RouteAttribute, RouteMessage},
    rule::{RuleAttribute, RuleMessage},
};
use rtnetlink::{Handle, IpVersion, new_connection};

pub struct NetlinkBackend {
    rt: tokio::runtime::Runtime,
    handle: Handle,
}

impl NetlinkBackend {
    pub fn new() -> io::Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let handle = rt.block_on(async {
            let (connection, handle, _) = new_connection()?;
            tokio::spawn(connection);
            Ok::<Handle, io::Error>(handle)
        })?;
        Ok(Self { rt, handle })
    }
}

fn nl_err(e: rtnetlink::Error) -> io::Error {
    io::Error::other(format!("netlink: {e}"))
}

impl RouteBackend for NetlinkBackend {
    fn snapshot(&self) -> io::Result<ObservedState> {
        self.rt.block_on(async {
            let mut state = ObservedState::default();

            let mut addrs = self.handle.address().get().execute();
            while let Some(msg) = addrs
                .try_next()
                .await
                .map_err(|e| io::Error::other(format!("addr stream: {e}")))?
            {
                if let Some(a) = parse_address(&msg) {
                    state.addresses.push(a);
                }
            }

            for v in [IpVersion::V4, IpVersion::V6] {
                let mut routes = self.handle.route().get(v).execute();
                while let Some(msg) = routes
                    .try_next()
                    .await
                    .map_err(|e| io::Error::other(format!("route stream: {e}")))?
                {
                    if let Some(r) = parse_route(&msg) {
                        state.routes.push(r);
                    }
                }
            }

            for v in [IpVersion::V4, IpVersion::V6] {
                let mut rules = self.handle.rule().get(v).execute();
                while let Some(msg) = rules
                    .try_next()
                    .await
                    .map_err(|e| io::Error::other(format!("rule stream: {e}")))?
                {
                    if let Some(r) = parse_rule(&msg) {
                        state.rules.push(r);
                    }
                }
            }

            Ok(state)
        })
    }

    fn apply(&self, op: &RouteOp) -> io::Result<()> {
        self.rt.block_on(async { self.apply_inner(op).await })
    }

    fn is_in_effect(&self, op: &RouteOp) -> io::Result<bool> {
        let snap = self.snapshot()?;
        Ok(match op {
            RouteOp::AddAddress(a) | RouteOp::RemoveAddress(a) => snap.addresses.contains(a),
            RouteOp::AddRoute(r) | RouteOp::RemoveRoute(r) => snap.routes.contains(r),
            RouteOp::AddRule(r) | RouteOp::RemoveRule(r) => snap.rules.contains(r),
        })
    }
}

impl NetlinkBackend {
    async fn apply_inner(&self, op: &RouteOp) -> io::Result<()> {
        match op {
            RouteOp::AddAddress(a) => self.add_address(a).await,
            RouteOp::RemoveAddress(a) => self.remove_address(a).await,
            RouteOp::AddRoute(r) => self.add_route(r).await,
            RouteOp::RemoveRoute(r) => self.remove_route(r).await,
            RouteOp::AddRule(r) => self.add_rule(r).await,
            RouteOp::RemoveRule(r) => self.remove_rule(r).await,
        }
    }

    async fn add_address(&self, addr: &InterfaceAddress) -> io::Result<()> {
        let ifindex = resolve_ifindex(&addr.interface)?;
        self.handle
            .address()
            .add(ifindex, addr.prefix.addr(), addr.prefix.prefix_len())
            .execute()
            .await
            .map_err(nl_err)
    }

    async fn remove_address(&self, addr: &InterfaceAddress) -> io::Result<()> {
        let ifindex = resolve_ifindex(&addr.interface)?;
        let mut msg = AddressMessage::default();
        msg.header.prefix_len = addr.prefix.prefix_len();
        msg.header.index = ifindex;
        msg.header.family = match addr.prefix {
            IpNet::V4(_) => AddressFamily::Inet,
            IpNet::V6(_) => AddressFamily::Inet6,
        };
        let ip = addr.prefix.addr();
        msg.attributes.push(AddressAttribute::Address(ip));
        msg.attributes.push(AddressAttribute::Local(ip));
        self.handle
            .address()
            .del(msg)
            .execute()
            .await
            .map_err(nl_err)
    }

    async fn add_route(&self, entry: &RouteEntry) -> io::Result<()> {
        let dest = entry.destination.addr();
        let plen = entry.destination.prefix_len();

        let result = match dest {
            IpAddr::V4(ip) => {
                let mut req = self
                    .handle
                    .route()
                    .add()
                    .v4()
                    .destination_prefix(ip, plen)
                    .table_id(entry.table);
                if let Some(gw) = entry.gateway.and_then(|g| match g {
                    IpAddr::V4(v) => Some(v),
                    _ => None,
                }) {
                    req = req.gateway(gw);
                }
                if let Some(iface) = &entry.interface {
                    let idx = resolve_ifindex(iface)?;
                    req = req.output_interface(idx);
                }
                req.execute().await
            }
            IpAddr::V6(ip) => {
                let mut req = self
                    .handle
                    .route()
                    .add()
                    .v6()
                    .destination_prefix(ip, plen)
                    .table_id(entry.table);
                if let Some(gw) = entry.gateway.and_then(|g| match g {
                    IpAddr::V6(v) => Some(v),
                    _ => None,
                }) {
                    req = req.gateway(gw);
                }
                if let Some(iface) = &entry.interface {
                    let idx = resolve_ifindex(iface)?;
                    req = req.output_interface(idx);
                }
                req.execute().await
            }
        };
        result.map_err(nl_err)
    }

    async fn remove_route(&self, entry: &RouteEntry) -> io::Result<()> {
        let mut msg = RouteMessage::default();
        msg.header.address_family = match entry.destination {
            IpNet::V4(_) => AddressFamily::Inet,
            IpNet::V6(_) => AddressFamily::Inet6,
        };
        msg.header.destination_prefix_length = entry.destination.prefix_len();
        msg.header.table = entry.table as u8;
        if entry.table > 255 {
            msg.attributes.push(RouteAttribute::Table(entry.table));
        }
        let route_addr = match entry.destination.addr() {
            IpAddr::V4(a) => netlink_packet_route::route::RouteAddress::Inet(a),
            IpAddr::V6(a) => netlink_packet_route::route::RouteAddress::Inet6(a),
        };
        msg.attributes.push(RouteAttribute::Destination(route_addr));
        self.handle.route().del(msg).execute().await.map_err(nl_err)
    }

    async fn add_rule(&self, rule: &PolicyRule) -> io::Result<()> {
        let table = match rule.action {
            RuleAction::Lookup(t) => t,
            _ => 0,
        };
        let prio = rule.priority;
        let (dest, plen) = rule
            .selector
            .destination
            .map(|d| (d.addr(), d.prefix_len()))
            .unwrap_or((IpAddr::from([0, 0, 0, 0]), 0));

        let result = match dest {
            IpAddr::V4(d) => {
                self.handle
                    .rule()
                    .add()
                    .v4()
                    .priority(prio)
                    .table_id(table)
                    .destination_prefix(d, plen)
                    .execute()
                    .await
            }
            IpAddr::V6(d) => {
                self.handle
                    .rule()
                    .add()
                    .v6()
                    .priority(prio)
                    .table_id(table)
                    .destination_prefix(d, plen)
                    .execute()
                    .await
            }
        };
        result.map_err(nl_err)
    }

    async fn remove_rule(&self, rule: &PolicyRule) -> io::Result<()> {
        let mut msg = RuleMessage::default();
        let table = match rule.action {
            RuleAction::Lookup(t) => t,
            _ => 0,
        };
        msg.header.table = table as u8;
        msg.header.family = match rule.selector.destination.map(|d| d.addr()) {
            Some(IpAddr::V6(_)) | None => AddressFamily::Inet6,
            Some(IpAddr::V4(_)) => AddressFamily::Inet,
        };
        msg.attributes.push(RuleAttribute::Priority(rule.priority));
        if let Some(dest) = &rule.selector.destination {
            msg.attributes.push(RuleAttribute::Destination(dest.addr()));
        }
        self.handle.rule().del(msg).execute().await.map_err(nl_err)
    }
}

// Interface-name resolution is the second sanctioned unsafe spot (the
// first being fd adoption in the device crate). Both carry their
// reasoning inline.
#[expect(unsafe_code)]
fn resolve_ifindex(name: &str) -> io::Result<u32> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name"))?;
    // SAFETY: the pointer comes from a valid CString that outlives the
    // call; if_nametoindex reads it and returns an integer.
    let index = unsafe { if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface not found: {name}"),
        ));
    }
    Ok(index)
}

// SAFETY: this extern declaration matches the C ABI of
// if_nametoindex(3), which takes a NUL-terminated name and returns u32.
#[expect(unsafe_code)]
unsafe extern "C" {
    #[link_name = "if_nametoindex"]
    fn if_nametoindex(ifname: *const std::ffi::c_char) -> u32;
}

fn parse_address(msg: &AddressMessage) -> Option<InterfaceAddress> {
    let prefix_len = msg.header.prefix_len;
    let mut ip = None;
    let mut label = None;
    for attr in &msg.attributes {
        match attr {
            AddressAttribute::Address(addr) => ip = Some(*addr),
            AddressAttribute::Local(addr) => {
                if ip.is_none() {
                    ip = Some(*addr);
                }
            }
            AddressAttribute::Label(name) => label = Some(name.clone()),
            _ => {}
        }
    }
    let ip = ip?;
    let prefix = match ip {
        IpAddr::V4(a) => IpNet::V4(ipnet::Ipv4Net::new(a, prefix_len).ok()?),
        IpAddr::V6(a) => IpNet::V6(ipnet::Ipv6Net::new(a, prefix_len).ok()?),
    };
    let name = label.unwrap_or_else(|| format!("if{}", msg.header.index));
    Some(InterfaceAddress {
        interface: name,
        prefix,
    })
}

fn parse_route(msg: &RouteMessage) -> Option<RouteEntry> {
    let mut table = msg.header.table.into();
    let mut dest_ip: Option<IpAddr> = None;
    let mut gateway: Option<IpAddr> = None;

    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Table(t) => table = *t,
            RouteAttribute::Destination(addr) => {
                dest_ip = match addr {
                    netlink_packet_route::route::RouteAddress::Inet(a) => Some(IpAddr::V4(*a)),
                    netlink_packet_route::route::RouteAddress::Inet6(a) => Some(IpAddr::V6(*a)),
                    _ => None,
                };
            }
            RouteAttribute::Gateway(addr) => {
                gateway = match addr {
                    netlink_packet_route::route::RouteAddress::Inet(a) => Some(IpAddr::V4(*a)),
                    netlink_packet_route::route::RouteAddress::Inet6(a) => Some(IpAddr::V6(*a)),
                    _ => None,
                };
            }
            _ => {}
        }
    }

    let family = msg.header.address_family;
    let dest_ip = dest_ip.unwrap_or(match family {
        AddressFamily::Inet => IpAddr::from([0, 0, 0, 0]),
        AddressFamily::Inet6 => IpAddr::from([0u8; 16]),
        _ => return None,
    });
    let plen = msg.header.destination_prefix_length;
    let prefix = match dest_ip {
        IpAddr::V4(a) => IpNet::V4(ipnet::Ipv4Net::new(a, plen).ok()?),
        IpAddr::V6(a) => IpNet::V6(ipnet::Ipv6Net::new(a, plen).ok()?),
    };

    Some(RouteEntry {
        table,
        destination: prefix,
        gateway,
        interface: None,
        metric: 0,
    })
}

fn parse_rule(msg: &RuleMessage) -> Option<PolicyRule> {
    let table = msg.header.table.into();
    let mut priority = 0u32;
    let mut destination = None;

    for attr in &msg.attributes {
        match attr {
            RuleAttribute::Priority(p) => priority = *p,
            RuleAttribute::Destination(ip) => {
                let plen = msg.header.dst_len;
                destination = Some(match *ip {
                    IpAddr::V4(a) => IpNet::V4(ipnet::Ipv4Net::new(a, plen).ok()?),
                    IpAddr::V6(a) => IpNet::V6(ipnet::Ipv6Net::new(a, plen).ok()?),
                });
            }
            _ => {}
        }
    }

    Some(PolicyRule {
        priority,
        selector: RuleSelector {
            source: None,
            destination,
            incoming_interface: None,
            suppress_prefixlen: None,
            dport: None,
        },
        action: RuleAction::Lookup(table),
        tag: String::new(),
    })
}
