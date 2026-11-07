// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The Windows firewall posture: an inbound-allow rule for the
//! running executable, added when a capture starts and removed when
//! it ends. The system's own firewall COM API (INetFwPolicy2) does
//! the editing; a default-deny firewall otherwise swallows the very
//! packets the TUN hands this process. The documented mode prints the
//! equivalent netsh commands instead, for hosts whose policy forbids
//! programmatic rule edits.

use std::io;

use vfawn_core::WindowsFirewallMode;
use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION_ALLOW, NET_FW_IP_PROTOCOL_TCP,
    NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN, NetFwPolicy2 as ClsidPolicy, NetFwRule as ClsidRule,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoUninitialize,
};

/// The rule name prefix; the executable's absolute path completes it,
/// so two builds running side by side carry two rules and one name
/// always maps to one binary.
const NAME_PREFIX: &str = "vfawn (";

/// The rule name for this process's executable.
pub fn rule_name() -> String {
    format!("{NAME_PREFIX}{})", executable_path().display())
}

/// Apply the configured posture. Returns the rule's name when a rule
/// is (or will be) in effect — Auto added it, Documented printed the
/// command — so the caller's cleanup removes the same thing it would
/// have. Disabled returns None and touches nothing.
pub fn apply(mode: WindowsFirewallMode) -> io::Result<Option<String>> {
    let name = rule_name();
    match mode {
        WindowsFirewallMode::Disabled => Ok(None),
        WindowsFirewallMode::Documented => {
            println!("{}", documented_add(&name));
            Ok(Some(name))
        }
        WindowsFirewallMode::Auto => {
            add(&name)?;
            Ok(Some(name))
        }
    }
}

/// Remove this process's rule if it stands. Idempotent: a rule that
/// never existed is as gone as one that did.
pub fn remove() -> io::Result<()> {
    let name = rule_name();
    with_policy(|rules| {
        // SAFETY: the COM call takes the name we built; a missing rule
        // reports an error the caller treats as success.
        #[expect(unsafe_code)]
        let removed = unsafe { rules.Remove(&name.into()) };
        match removed {
            Ok(()) => Ok(()),
            Err(_) => Ok(()), // not there: already gone
        }
    })
}

/// The netsh command pair a host administrator runs by hand. These are
/// the documented mode's whole output and the Auto mode's manual
/// fallback.
pub fn documented_add(name: &str) -> String {
    format!(
        "netsh advfirewall firewall add rule name=\"{name}\" dir=in action=allow protocol=TCP program=\"{}\" enable=yes profile=any",
        executable_path().display()
    )
}

/// The one-frame COM session: apartment-threaded init, the policy
/// object, its rules collection, then the caller's work — uninit last.
fn with_policy<T>(work: impl FnOnce(&INetFwRules) -> io::Result<T>) -> io::Result<T> {
    // SAFETY: COM initialization on this thread; the matching
    // uninitialize runs on every exit path below, and no COM pointer
    // outlives the scope the apartment covers.
    #[expect(unsafe_code)]
    let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    // A thread already parked in the other apartment model lends its
    // apartment to this call — the pointers work, and the uninit below
    // belongs to whoever initialized, not to us. Any other failure is
    // real.
    let borrowed_apartment = hr == RPC_E_CHANGED_MODE;
    if hr.is_err() && !borrowed_apartment {
        return Err(io::Error::other(format!("CoInitializeEx failed: {hr:?}")));
    }
    let result = (|| {
        // SAFETY: the CLSID and interface identity are the platform's
        // own constants; the object lives in-process for this scope.
        #[expect(unsafe_code)]
        let policy: INetFwPolicy2 = unsafe {
            CoCreateInstance(&ClsidPolicy, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| io::Error::other(format!("firewall policy object: {e}")))?
        };
        // SAFETY: property fetch on a live object in this apartment.
        #[expect(unsafe_code)]
        let rules: INetFwRules = unsafe {
            policy
                .Rules()
                .map_err(|e| io::Error::other(format!("firewall rules collection: {e}")))?
        };
        work(&rules)
    })();
    if !borrowed_apartment {
        // SAFETY: the matching uninit for the init above; every COM
        // pointer is dropped by now.
        #[expect(unsafe_code)]
        unsafe {
            CoUninitialize();
        }
    }
    result
}

/// Add the inbound-allow rule for this executable, idempotently: a
/// rule already standing under the name is the destination state.
fn add(name: &str) -> io::Result<()> {
    with_policy(|rules| {
        let name_bstr: windows::core::BSTR = name.into();
        // SAFETY: a lookup by name on a live collection.
        #[expect(unsafe_code)]
        let standing = unsafe { rules.Item(&name_bstr) }.is_ok();
        if standing {
            return Ok(());
        }
        // SAFETY: rule object creation in this apartment.
        #[expect(unsafe_code)]
        let rule: INetFwRule = unsafe {
            CoCreateInstance(&ClsidRule, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| io::Error::other(format!("firewall rule object: {e}")))?
        };
        // SAFETY: property writes on the freshly created rule.
        #[expect(unsafe_code)]
        unsafe {
            rule.SetName(&name_bstr)
                .and_then(|()| {
                    rule.SetDescription(&windows::core::BSTR::from(
                        "vfawn capture: allow the process's own inbound TCP",
                    ))
                })
                .and_then(|()| {
                    rule.SetApplicationName(&windows::core::BSTR::from(
                        executable_path().to_string_lossy().as_ref(),
                    ))
                })
                .and_then(|()| rule.SetProtocol(NET_FW_IP_PROTOCOL_TCP.0))
                .and_then(|()| rule.SetDirection(NET_FW_RULE_DIR_IN))
                .and_then(|()| rule.SetAction(NET_FW_ACTION_ALLOW))
                .and_then(|()| rule.SetProfiles(NET_FW_PROFILE2_ALL.0))
                .and_then(|()| rule.SetEnabled(windows::Win32::Foundation::VARIANT_BOOL(1)))
                .map_err(|e| io::Error::other(format!("firewall rule fields: {e}")))?;
            rules
                .Add(&rule)
                .map_err(|e| io::Error::other(format!("firewall rule add: {e}")))
        }
    })
}

/// This process's absolute executable path, the rule's identity.
fn executable_path() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("vfawn"))
}
