// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The Windows route backend: routes and addresses through the
//! system's own IP Helper API, snapshots from the same tables. There
//! is exactly one routing table and no policy rule object on this
//! platform — the Linux rule concept maps to interface routes at the
//! desired-state layer before it reaches here, so the rule operations
//! are facts the adapter layer already expressed. Addresses ride the
//! device layer (adapter creation sets them), as on darwin: the route
//! engine's model sees them as facts, not operations.

use std::io;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use vfawn_route::backend::RouteBackend;
use vfawn_route::model::{ObservedState, RouteEntry, RouteOp};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetAdaptersAddresses,
    GetIpForwardEntry2, GetIpForwardTable2, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
    InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

/// The Windows route backend. One platform, one table, typed rows.
#[derive(Default)]
pub struct WindowsRouteBackend;

impl WindowsRouteBackend {
    pub fn new() -> Self {
        Self
    }
}

impl RouteBackend for WindowsRouteBackend {
    #[expect(unsafe_code)]
    fn snapshot(&self) -> io::Result<ObservedState> {
        let snapshot = adapter_snapshot()?;
        let adapters = &snapshot.adapters;
        let mut routes = Vec::new();
        unsafe {
            let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
            if GetIpForwardTable2(AF_INET, &mut table) != ERROR_SUCCESS || table.is_null() {
                return Ok(ObservedState::default());
            }
            // SAFETY: the table's own header says how many rows follow
            // it; the kernel allocated them as one block this call now
            // owns until the free below.
            let count = (*table).NumEntries as usize;
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
            for row in rows {
                let Some(destination) = prefix_of(row) else {
                    continue;
                };
                let interface = adapters
                    .iter()
                    .find(|adapter| adapter.index == row.InterfaceIndex)
                    .map(|adapter| adapter.name.clone());
                routes.push(RouteEntry {
                    table: 0, // one table on this platform
                    destination,
                    gateway: next_hop_of(row),
                    interface,
                    metric: row.Metric,
                });
            }
            FreeMibTable(table.cast());
        }
        Ok(ObservedState {
            addresses: snapshot.addresses,
            routes,
            rules: Vec::new(),
        })
    }

    fn apply(&self, op: &RouteOp) -> io::Result<()> {
        match op {
            RouteOp::AddRoute(entry) => self.add_route(entry),
            RouteOp::RemoveRoute(entry) => self.remove_route(entry),
            // Addresses ride the device layer (adapter creation), and
            // this platform has no policy rule object: both are facts
            // the desired state's adapter layer already expressed.
            RouteOp::AddAddress(_) | RouteOp::RemoveAddress(_) => Ok(()),
            RouteOp::AddRule(_) | RouteOp::RemoveRule(_) => Ok(()),
        }
    }

    fn is_in_effect(&self, op: &RouteOp) -> io::Result<bool> {
        let state = self.snapshot()?;
        match op {
            RouteOp::AddRoute(entry) => Ok(state.routes.iter().any(|route| {
                route.destination == entry.destination && route.interface == entry.interface
            })),
            RouteOp::RemoveRoute(entry) => Ok(!state
                .routes
                .iter()
                .any(|route| route.destination == entry.destination)),
            RouteOp::AddAddress(_) | RouteOp::RemoveAddress(_) => Ok(true),
            RouteOp::AddRule(_) | RouteOp::RemoveRule(_) => Ok(true),
        }
    }
}

impl WindowsRouteBackend {
    #[expect(unsafe_code)]
    fn add_route(&self, entry: &RouteEntry) -> io::Result<()> {
        let adapters = adapter_snapshot()?.adapters;
        let index = adapters
            .iter()
            .find(|adapter| Some(&adapter.name) == entry.interface.as_ref())
            .map(|adapter| adapter.index)
            .ok_or_else(|| {
                io::Error::other(format!(
                    "route interface {:?} does not exist",
                    entry.interface
                ))
            })?;
        unsafe {
            let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            InitializeIpForwardEntry(&mut row);
            row.InterfaceIndex = index;
            row.DestinationPrefix.Prefix = sockaddr_of(&network_of(entry));
            row.DestinationPrefix.PrefixLength = entry.destination.prefix_len();
            row.NextHop = match entry.gateway {
                Some(gateway) => sockaddr_of(&gateway),
                None => std::mem::zeroed(),
            };
            row.Metric = entry.metric.max(1);
            let code = CreateIpForwardEntry2(&row);
            // The kernel's own idempotence: a row already in the table
            // is the destination state, not an error.
            if code == ERROR_SUCCESS || code == ERROR_OBJECT_ALREADY_EXISTS {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "CreateIpForwardEntry2 failed with code {code}"
                )))
            }
        }
    }

    #[expect(unsafe_code)]
    fn remove_route(&self, entry: &RouteEntry) -> io::Result<()> {
        let adapters = adapter_snapshot()?.adapters;
        let Some(index) = adapters
            .iter()
            .find(|adapter| Some(&adapter.name) == entry.interface.as_ref())
            .map(|adapter| adapter.index)
        else {
            // The interface is already gone; so is its route.
            return Ok(());
        };
        unsafe {
            let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            InitializeIpForwardEntry(&mut row);
            row.InterfaceIndex = index;
            row.DestinationPrefix.Prefix = sockaddr_of(&network_of(entry));
            row.DestinationPrefix.PrefixLength = entry.destination.prefix_len();
            row.NextHop = match entry.gateway {
                Some(gateway) => sockaddr_of(&gateway),
                None => std::mem::zeroed(),
            };
            // The delete wants a fully initialized row: the query
            // fills in everything the prefix and next hop identify.
            let found = GetIpForwardEntry2(&mut row);
            if found == ERROR_NOT_FOUND {
                return Ok(());
            }
            if found != ERROR_SUCCESS {
                return Err(io::Error::other(format!(
                    "GetIpForwardEntry2 failed with code {found}"
                )));
            }
            let code = DeleteIpForwardEntry2(&row);
            if code == ERROR_SUCCESS || code == ERROR_NOT_FOUND {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "DeleteIpForwardEntry2 failed with code {code}"
                )))
            }
        }
    }
}

/// One adapter as the route tables name them.
pub(crate) struct Adapter {
    pub(crate) name: String,
    pub(crate) index: u32,
    pub(crate) up: bool,
}

/// Everything one adapters query yields: the adapters themselves and
/// their unicast addresses, from the same kernel fill — two shapes,
/// one buffer, no second call.
#[derive(Default)]
pub(crate) struct AdapterSnapshot {
    pub(crate) adapters: Vec<Adapter>,
    pub(crate) addresses: Vec<vfawn_route::model::InterfaceAddress>,
}

/// Query the adapters and their addresses.
///
/// SAFETY discipline: GetAdaptersAddresses is the two-call size
/// pattern — the buffer is caller-owned memory the kernel fills with
/// a linked list whose strings are wide; every pointer dereference
/// below stays inside the buffer the call reported success on, and
/// the buffer's ownership ends with the walk.
#[expect(unsafe_code)]
pub(crate) fn adapter_snapshot() -> io::Result<AdapterSnapshot> {
    const FLAGS: u32 = 0x02 | 0x04 | 0x08; // skip anycast/multicast/dns
    let mut buffer: Vec<u8> = Vec::with_capacity(16 * 1024);
    loop {
        let mut size = buffer.capacity() as u32;
        let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let code = unsafe {
            GetAdaptersAddresses(AF_INET as u32, FLAGS, std::ptr::null(), head, &mut size)
        };
        if code == ERROR_SUCCESS {
            let snapshot = unsafe { walk(head) };
            return Ok(snapshot);
        }
        // 111 = ERROR_BUFFER_OVERFLOW: the call reports the size it
        // wanted and fills nothing; grow and retry.
        if code == 111 {
            buffer.reserve((size as usize).saturating_sub(buffer.capacity()) + 1);
            continue;
        }
        return Err(io::Error::other(format!(
            "GetAdaptersAddresses failed with code {code}"
        )));
    }
}

/// Walk the adapters list the call built inside the buffer, gathering
/// both shapes in one pass.
///
/// # Safety
///
/// `head` must be the list head of a successful GetAdaptersAddresses
/// fill into memory this caller owns and outlives the walk.
#[expect(unsafe_code)]
unsafe fn walk(head: *mut IP_ADAPTER_ADDRESSES_LH) -> AdapterSnapshot {
    let mut adapters = Vec::new();
    let mut addresses = Vec::new();
    let mut current = head;
    // SAFETY: every node, string, and address below lives inside the
    // buffer the caller owns; the walk only reads it, and the
    // lifetime ends when the walk does.
    unsafe {
        while !current.is_null() {
            let node = &*current;
            if !node.FriendlyName.is_null() {
                let name = friendly_name(node.FriendlyName);
                adapters.push(Adapter {
                    name: name.clone(),
                    index: node.Anonymous1.Anonymous.IfIndex,
                    up: node.OperStatus == IfOperStatusUp,
                });
                let mut unicast = node.FirstUnicastAddress;
                while !unicast.is_null() {
                    let entry: &IP_ADAPTER_UNICAST_ADDRESS_LH = &*unicast;
                    if !entry.Address.lpSockaddr.is_null() {
                        let sockaddr = &*entry.Address.lpSockaddr.cast::<SOCKADDR_INET>();
                        if let Some(IpAddr::V4(address)) = ip_of(sockaddr) {
                            let length = (entry.OnLinkPrefixLength as u32).min(32);
                            let masked = Ipv4Addr::from(u32::from(address) & prefix_mask(length));
                            addresses.push(vfawn_route::model::InterfaceAddress {
                                interface: name.clone(),
                                prefix: IpNet::new(masked.into(), length as u8).unwrap_or(
                                    IpNet::new(masked.into(), 32).expect("32 is a legal length"),
                                ),
                            });
                        }
                    }
                    unicast = entry.Next;
                }
            }
            current = node.Next;
        }
    }
    AdapterSnapshot {
        adapters,
        addresses,
    }
}

/// One wide string from the adapters buffer.
///
/// # Safety
///
/// `pointer` must be NUL-terminated wide characters inside a buffer
/// this caller owns.
#[expect(unsafe_code)]
unsafe fn friendly_name(pointer: windows_sys::core::PWSTR) -> String {
    // SAFETY: the contract above.
    unsafe {
        let mut length = 0usize;
        while *pointer.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length))
    }
}

/// The entry's destination as the kernel wants it: a prefix carries
/// no host bits, and the model's IpNet tolerates them, so the
/// platform boundary masks on the way in.
fn network_of(entry: &RouteEntry) -> IpAddr {
    entry.destination.network()
}

/// A prefix length as an address mask.
fn prefix_mask(length: u32) -> u32 {
    if length == 0 {
        0
    } else {
        u32::MAX << (32 - length.min(32))
    }
}

/// The row's destination prefix, when it is an IPv4 prefix this
/// model can hold.
///
/// # Safety
///
/// `row` must point at a kernel-filled row inside the snapshot table.
#[expect(unsafe_code)]
unsafe fn prefix_of(row: &MIB_IPFORWARD_ROW2) -> Option<IpNet> {
    // SAFETY: reading the union by the family the kernel wrote.
    unsafe {
        let sockaddr = &row.DestinationPrefix.Prefix;
        let ip = ip_of(sockaddr)?;
        let address = match ip {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => return None,
        };
        let length = row.DestinationPrefix.PrefixLength;
        if length > 32 {
            return None;
        }
        let masked = Ipv4Addr::from(u32::from(address) & prefix_mask(length as u32));
        IpNet::new(masked.into(), length).ok()
    }
}

/// The row's next hop, when it names one.
///
/// # Safety
///
/// `row` must point at a kernel-filled row inside the snapshot table.
#[expect(unsafe_code)]
unsafe fn next_hop_of(row: &MIB_IPFORWARD_ROW2) -> Option<IpAddr> {
    // SAFETY: reading the union by the family the kernel wrote; an
    // all-zero address is the on-link shape, not a hop.
    unsafe {
        let sockaddr = &row.NextHop;
        let address = ip_of(sockaddr)?;
        match address {
            IpAddr::V4(address) if address != Ipv4Addr::UNSPECIFIED => Some(IpAddr::V4(address)),
            _ => None,
        }
    }
}

/// Read one inet sockaddr by the family it carries.
///
/// # Safety
///
/// `sockaddr` must point at kernel-initialized union storage.
#[expect(unsafe_code)]
unsafe fn ip_of(sockaddr: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: the family discriminates the union; IPv4 is the only
    // family this backend speaks.
    unsafe {
        if sockaddr.si_family != AF_INET {
            return None;
        }
        let v4 = &sockaddr.Ipv4;
        // The address word holds the four octets in network order;
        // the swap puts them back into the integer the constructor
        // wants. Windows is little-endian in every target this
        // builds for.
        let octets = v4.sin_addr.S_un.S_addr.swap_bytes();
        Some(IpAddr::V4(Ipv4Addr::from(octets)))
    }
}

/// Write one address into a fresh inet sockaddr.
#[expect(unsafe_code)]
fn sockaddr_of(address: &IpAddr) -> SOCKADDR_INET {
    // SAFETY: the union write follows the family the same lines set;
    // SOCKADDR_INET is all-plain-data with no invariants.
    unsafe {
        let mut sockaddr: SOCKADDR_INET = std::mem::zeroed();
        if let IpAddr::V4(v4) = address {
            sockaddr.Ipv4.sin_family = AF_INET;
            sockaddr.Ipv4.sin_addr.S_un.S_addr = u32::from(*v4).swap_bytes();
        }
        sockaddr
    }
}
