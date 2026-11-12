// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! Behavior shared across Unix targets: adopted-fd handling for hosts that
//! supply the device (VPN services, network extensions) and interface-bound
//! sockets for the anti-loopback path.

/// The kernel's index for the interface named `name`, or `None` when no
/// such interface exists (or the name cannot be one).
// Interface-name resolution is one of the sanctioned unsafe spots (fd
// adoption in the device crate is another); the reasoning is inline.
#[expect(unsafe_code)]
pub fn interface_index(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: the pointer comes from a valid CString that outlives the
    // call; if_nametoindex reads it and returns an integer.
    let index = unsafe { if_nametoindex(cname.as_ptr()) };
    (index != 0).then_some(index)
}

// SAFETY: this extern declaration matches the C ABI of
// if_nametoindex(3), which takes a NUL-terminated name and returns u32.
#[expect(unsafe_code)]
unsafe extern "C" {
    #[link_name = "if_nametoindex"]
    fn if_nametoindex(ifname: *const std::ffi::c_char) -> u32;
}
