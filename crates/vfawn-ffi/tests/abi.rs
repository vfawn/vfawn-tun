// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The ABI's own tests: the header regenerates byte-for-byte (the
//! checked-in copy cannot drift), and hostile inputs — oversized,
//! deeply nested, malformed — answer error codes instead of crashing.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

use vfawn_ffi::*;

const GOOD_CONFIG: &str =
    r#"{"device":{"mtu":1500,"inet4_address":["198.18.0.1/15"]},"route":{"auto_route":false}}"#;

fn c_str(text: &str) -> CString {
    CString::new(text).expect("test strings carry no NULs")
}

/// The C API as C would call it.
///
/// # Safety
///
/// The pointers must be valid for the call; every caller below builds
/// them from live locals.
#[expect(unsafe_code)]
unsafe fn validate(json: &CStr, err: &mut [u8]) -> c_int {
    // SAFETY: the boundary contract with valid pointers.
    unsafe { vfawn_config_validate(json.as_ptr(), err.as_mut_ptr() as *mut c_char, err.len()) }
}

#[test]
fn the_header_regenerates_byte_for_byte() {
    let bindings = cbindgen::generate(".").expect("the crate parses");
    let generated = {
        let mut buffer = Vec::new();
        bindings.write(&mut buffer);
        String::from_utf8(buffer).expect("the header is UTF-8")
    };
    let header = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("include/vfawn.h");
    if std::env::var_os("VFAWN_REGEN_HEADER").is_some() {
        std::fs::create_dir_all(header.parent().expect("a parent")).expect("the include dir");
        std::fs::write(&header, &generated).expect("write the regenerated header");
        return;
    }
    let checked_in = std::fs::read_to_string(&header).expect("the checked-in header");
    assert_eq!(
        generated, checked_in,
        "include/vfawn.h drifted; regenerate with VFAWN_REGEN_HEADER=1 cargo test -p vfawn-ffi"
    );
}

/// The C sources a host compiles stay ASCII: MSVC reads a BOM-less
/// file in the system code page (936 on Chinese Windows) and warns
/// C4819 on anything outside it, which `/WX` turns into a failure.
#[test]
fn the_c_sources_are_ascii() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for file in ["include/vfawn.h", "examples/c/lifecycle.c"] {
        let text = std::fs::read_to_string(root.join(file)).expect("the C source");
        let offender = text.lines().enumerate().find(|(_, line)| !line.is_ascii());
        assert!(
            offender.is_none(),
            "{file}:{} is not ASCII; the doc comments in src/ feed the header",
            offender.map_or(0, |(index, _)| index + 1)
        );
    }
}

#[test]
fn a_good_configuration_validates() {
    let mut err = [0u8; 256];
    // SAFETY: live locals, per the helper's contract.
    #[expect(unsafe_code)]
    let code = unsafe { validate(&c_str(GOOD_CONFIG), &mut err) };
    assert_eq!(code, VFAWN_OK);
}

#[test]
fn hostile_documents_answer_codes() {
    let mut err = [0u8; 256];
    let nested = format!("{}{}", "{\"device\":", "[".repeat(5000));
    for hostile in [
        "{ not json at all",
        "{\"device\":{\"mtu\":-1}}",
        "{\"device\":{\"mtu\":999999}}",
        nested.as_str(),
    ] {
        // SAFETY: live locals.
        #[expect(unsafe_code)]
        let code = unsafe { validate(&c_str(hostile), &mut err) };
        assert_eq!(
            code,
            VFAWN_ERR_INVALID_CONFIG,
            "hostile input must answer the code, got {code} for {}…",
            &hostile[..hostile.len().min(40)],
        );
    }
}

#[test]
fn an_oversized_document_is_refused_before_parsing() {
    let mut err = [0u8; 256];
    let oversized = format!("{{\"pad\":\"{}\"}}", "x".repeat(1024 * 1024 + 16));
    // SAFETY: live locals.
    #[expect(unsafe_code)]
    let code = unsafe { validate(&c_str(&oversized), &mut err) };
    assert_eq!(code, VFAWN_ERR_INVALID_CONFIG);
}

#[test]
fn a_null_handle_is_bad_and_destroy_is_null_tolerant() {
    // SAFETY: the null handle is the tested input.
    #[expect(unsafe_code)]
    unsafe {
        assert_eq!(
            vfawn_instance_stats(VFAWN_NULL_HANDLE, std::ptr::null_mut()),
            VFAWN_ERR_BAD_HANDLE
        );
        vfawn_instance_destroy(VFAWN_NULL_HANDLE);
    }
}
