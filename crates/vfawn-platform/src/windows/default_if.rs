// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The default interface on Windows, chosen the way sing-tun's
//! `defaultInterfaceMonitor.checkUpdate` (`monitor_windows.go`)
//! chooses it: among the IPv4 default routes, the up, connected,
//! non-virtual, non-loopback interface with the lowest route metric
//! plus interface metric. The virtual-type filter is what keeps a TUN
//! that owns a default route (wintun reports `IF_TYPE_PROP_VIRTUAL`)
//! from being named as the way out.

use std::io;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfEntry2, GetIpForwardTable2, GetIpInterfaceEntry, IF_TYPE_PROP_VIRTUAL,
    IF_TYPE_SOFTWARE_LOOPBACK, InitializeIpInterfaceEntry, MIB_IF_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::AF_INET;

/// The interface the host's own traffic leaves through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultInterface {
    /// The interface alias (the friendly name the adapter list shows).
    pub name: String,
    /// The interface index `IP_UNICAST_IF` binds to.
    pub index: u32,
}

/// Read the current default interface; `None` when no interface
/// qualifies (sing-tun's `ErrNoRoute`).
#[expect(unsafe_code)]
pub fn current_default_interface() -> io::Result<Option<DefaultInterface>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: the kernel allocates the table and reports success before
    // anything reads it; the free below ends its lifetime.
    let code = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    if table.is_null() {
        return Ok(None);
    }
    let mut best: Option<(u32, DefaultInterface)> = None;
    // SAFETY: the rows are read inside the table's lifetime, bounded by
    // the count its own header carries; the per-interface rows are
    // zeroed locals the calls fill by LUID.
    unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            if row.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            let mut interface: MIB_IF_ROW2 = std::mem::zeroed();
            interface.InterfaceLuid = row.InterfaceLuid;
            if GetIfEntry2(&mut interface) != ERROR_SUCCESS
                || interface.OperStatus != IfOperStatusUp
            {
                continue;
            }
            if interface.Type == IF_TYPE_PROP_VIRTUAL || interface.Type == IF_TYPE_SOFTWARE_LOOPBACK
            {
                continue;
            }
            let mut ip: MIB_IPINTERFACE_ROW = std::mem::zeroed();
            InitializeIpInterfaceEntry(&mut ip);
            ip.Family = AF_INET;
            ip.InterfaceLuid = row.InterfaceLuid;
            if GetIpInterfaceEntry(&mut ip) != ERROR_SUCCESS || !ip.Connected {
                continue;
            }
            let metric = row.Metric.saturating_add(ip.Metric);
            if best.as_ref().is_none_or(|(lowest, _)| metric < *lowest) {
                best = Some((
                    metric,
                    DefaultInterface {
                        name: alias_of(&interface.Alias),
                        index: interface.InterfaceIndex,
                    },
                ));
            }
        }
        FreeMibTable(table.cast());
    }
    Ok(best.map(|(_, interface)| interface))
}

/// The NUL-terminated wide alias as a string.
fn alias_of(alias: &[u16]) -> String {
    let end = alias
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(alias.len());
    String::from_utf16_lossy(&alias[..end])
}
