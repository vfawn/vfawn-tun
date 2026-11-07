// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The C ABI: handles instead of object references, a generation
//! table so a stale handle cannot alias a live instance, every panic
//! caught at the boundary and translated to an error code, and
//! configuration carried as JSON rather than mirrored structs. This
//! crate translates; it decides nothing.
//!
//! The v0 data plane is the relay: the C host judges flows (the
//! verdict callback rides the wire's own judge seat) and sessions are
//! terminated by the built-in relay handler. Session-level transport
//! across the boundary is a later volume; the handle lifecycle here
//! is complete without it.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use vfawn::instance::{ApplyError, Instance, StatsSnapshot};
use vfawn::relay::RelayHandler;
use vfawn_core::{FlowInfo, SessionHandler, TcpSession, UdpSession, Verdict};

/// The ABI version this library speaks; bump on any breaking change.
pub const VFAWN_ABI_VERSION: u32 = 1;

/// A configuration document larger than this is refused before
/// parsing: the boundary's job is to bound what crosses it.
const CONFIG_LIMIT: usize = 1024 * 1024;

// --- Error codes: the whole vocabulary, zero is success ---------------

pub const VFAWN_OK: c_int = 0;
pub const VFAWN_ERR_INVALID_CONFIG: c_int = 1;
pub const VFAWN_ERR_ALREADY_RUNNING: c_int = 2;
pub const VFAWN_ERR_NOT_RUNNING: c_int = 3;
pub const VFAWN_ERR_UNSUPPORTED: c_int = 4;
pub const VFAWN_ERR_BAD_HANDLE: c_int = 5;
pub const VFAWN_ERR_BUFFER_TOO_SMALL: c_int = 6;
pub const VFAWN_ERR_NEEDS_RESTART: c_int = 7;
pub const VFAWN_ERR_PANIC: c_int = 8;
pub const VFAWN_ERR_REENTRANT: c_int = 9;

// --- Verdict codes the judge callback answers -------------------------

pub const VFAWN_VERDICT_ACCEPT: c_int = 0;
pub const VFAWN_VERDICT_BYPASS: c_int = 1;
pub const VFAWN_VERDICT_DROP: c_int = 2;
pub const VFAWN_VERDICT_REJECT: c_int = 3;

/// The handle: an index into the process-wide table paired with the
/// slot's generation. A destroyed slot's index recycles only with a
/// new generation, so a stale handle from an earlier life answers
/// [`VFAWN_ERR_BAD_HANDLE`], never a stranger.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct vfawn_instance_t {
    /// The table slot; zero only on the null handle.
    pub index: u32,
    /// The slot's life; a recycled index carries a new one.
    pub generation: u32,
}

/// The null handle: what creation answers when it fails, and the
/// value C initializes its variables to.
pub const VFAWN_NULL_HANDLE: vfawn_instance_t = vfawn_instance_t {
    index: 0,
    generation: 0,
};

/// The null handle, privately.
const NULL_HANDLE: vfawn_instance_t = VFAWN_NULL_HANDLE;

// --- The judge callback: the host's one synchronous seat --------------

/// The verdict callback. `flow_json` is a borrowed, NUL-terminated
/// JSON view of the flow (`{"source":"ip:port","destination":…,
/// "network":"tcp"}`) valid only for the call; copy what you keep.
/// The callback runs on a data-plane thread: it must not block and
/// must not reenter the ABI.
#[allow(non_camel_case_types)] // C names are the ABI
pub type vfawn_judge_fn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, flow_json: *const c_char) -> c_int>;

/// The vtable, versioned by size: later fields may be appended, a
/// smaller vtable from an older host leaves them null.
#[repr(C)]
pub struct vfawn_handler_vtable_t {
    /// `sizeof` at the host's compile time.
    pub size: usize,
    /// The host's own context, passed to every callback untouched.
    pub ctx: *mut c_void,
    /// The flow judge; None accepts everything (the relay default).
    pub judge_flow: vfawn_judge_fn,
}

// --- The stats view: four numbers, by value ---------------------------

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct vfawn_stats_t {
    pub sessions_total: u64,
    pub bytes_forward: u64,
    pub bytes_reverse: u64,
    pub panics_contained: u64,
}

// --- The table ---------------------------------------------------------

/// One slot's shareable body: the instance under its own lock, so a
/// long shutdown never blocks another instance's control calls.
struct SlotBody {
    instance: Mutex<Instance>,
    vtable: Mutex<Option<VtableRef>>,
    error: Mutex<CString>,
    /// Set once the instance started; cleared by shutdown. The
    /// vtable is only accepted before the first start.
    started: AtomicBool,
}

struct SlotEntry {
    generation: u32,
    body: Arc<SlotBody>,
}

struct Table {
    slots: Vec<Option<SlotEntry>>,
    next_generation: u32,
}

static TABLE: Mutex<Option<Table>> = Mutex::new(None);

/// The vtable as the instance keeps it, read by the size the host
/// declared: appended fields an older host never wrote read as None
/// rather than garbage.
struct VtableRef {
    judge: vfawn_judge_fn,
    ctx: *mut c_void,
}

// SAFETY: the vtable reference is read from data-plane threads and
// written only under the slot's lock before start; the host contract
// keeps the memory alive for the instance's lifetime.
#[expect(unsafe_code)]
unsafe impl Send for VtableRef {}
#[expect(unsafe_code)]
unsafe impl Sync for VtableRef {}

impl VtableRef {
    /// Read the judge slot from the host's vtable by its declared
    /// size.
    ///
    /// # Safety
    ///
    /// `raw` must point at readable memory whose first field (the
    /// size) is honest, and must stay readable for the instance's
    /// lifetime.
    #[expect(unsafe_code)]
    unsafe fn from_raw(raw: *const vfawn_handler_vtable_t) -> Option<Self> {
        // SAFETY: the contract above; the declared size gates the
        // field reads that follow it.
        unsafe {
            if raw.is_null() {
                return None;
            }
            let declared = (*raw).size;
            let judge_offset = std::mem::offset_of!(vfawn_handler_vtable_t, judge_flow);
            if declared < judge_offset + std::mem::size_of::<vfawn_judge_fn>() {
                return None; // a vtable too old to carry a judge
            }
            Some(Self {
                judge: (*raw).judge_flow,
                ctx: (*raw).ctx,
            })
        }
    }
}

/// Find a slot's body by handle: the table lock is held only for the
/// lookup, the body's own lock serializes the work.
fn body_of(handle: vfawn_instance_t) -> Option<Arc<SlotBody>> {
    let guard = TABLE.lock().ok()?;
    let table = guard.as_ref()?;
    match table.slots.get(handle.index as usize) {
        Some(Some(entry)) if entry.generation == handle.generation => Some(Arc::clone(&entry.body)),
        _ => None,
    }
}

/// Run `work` on the handle's body; the boundary's common shape.
fn with_body<T>(
    handle: vfawn_instance_t,
    work: impl FnOnce(&Arc<SlotBody>) -> Result<T, c_int>,
) -> Result<T, c_int> {
    if handle == NULL_HANDLE {
        return Err(VFAWN_ERR_BAD_HANDLE);
    }
    if reentrant() {
        return Err(VFAWN_ERR_REENTRANT);
    }
    match body_of(handle) {
        Some(body) => work(&body),
        None => Err(VFAWN_ERR_BAD_HANDLE),
    }
}

// --- The reentrancy guard ----------------------------------------------

thread_local! {
    static INSIDE_CALLBACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn reentrant() -> bool {
    INSIDE_CALLBACK.with(std::cell::Cell::get)
}

/// Record a failure's message in the slot's error cell.
fn remember_error(body: &SlotBody, message: &str) {
    if let Ok(mut cell) = body.error.lock()
        && let Ok(packed) = CString::new(message)
    {
        *cell = packed;
    }
}

// --- The host's handler -------------------------------------------------

/// The host's judge vtable wearing the session contract: verdicts
/// cross the boundary as codes, sessions terminate in the relay.
struct HostJudge(VtableRef);

#[async_trait::async_trait]
impl SessionHandler for HostJudge {
    fn judge_flow(&self, flow: &FlowInfo, _first_packet: &[u8]) -> Verdict {
        let Some(judge) = self.0.judge else {
            return Verdict::Accept;
        };
        let flow_json = serde_json::to_string(&FlowJson {
            source: flow.source.to_string(),
            destination: flow.destination.to_string(),
            network: match flow.network {
                vfawn_core::Network::Tcp => "tcp",
                vfawn_core::Network::Udp => "udp",
                _ => "icmp",
            },
        });
        let Ok(c_json) = CString::new(flow_json.unwrap_or_default()) else {
            return Verdict::Drop;
        };
        let answer = INSIDE_CALLBACK.with(|inside| {
            inside.set(true);
            // SAFETY: the host's callback runs with its own context
            // and a borrowed, valid C string; the flag above is what
            // keeps it from reentering.
            #[expect(unsafe_code)]
            let answer = unsafe { judge(self.0.ctx, c_json.as_ptr()) };
            inside.set(false);
            answer
        });
        match answer {
            VFAWN_VERDICT_BYPASS => Verdict::Bypass,
            VFAWN_VERDICT_DROP => Verdict::Drop,
            VFAWN_VERDICT_REJECT => Verdict::Reject,
            _ => Verdict::Accept,
        }
    }

    async fn on_tcp(&self, session: TcpSession) {
        RelayHandler::new(None).on_tcp(session).await;
    }

    async fn on_udp(&self, session: UdpSession) {
        RelayHandler::new(None).on_udp(session).await;
    }

    async fn on_icmp(&self, packet: vfawn_core::IcmpPacket) -> vfawn_core::Action {
        RelayHandler::new(None).on_icmp(packet).await
    }
}

#[derive(serde::Serialize)]
struct FlowJson {
    source: String,
    destination: String,
    network: &'static str,
}

// --- Boundary helpers ---------------------------------------------------

/// Catch a panic at the boundary and turn it into the panic code.
fn boundary<T>(work: impl std::panic::UnwindSafe + FnOnce() -> T) -> Result<T, c_int> {
    match std::panic::catch_unwind(work) {
        Ok(value) => Ok(value),
        Err(_) => Err(VFAWN_ERR_PANIC),
    }
}

/// Read a borrowed C string with a length cap; None on null, invalid
/// UTF-8, or a document over the cap.
fn borrowed_json(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the host lends a NUL-terminated string for the call.
    #[expect(unsafe_code)]
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    if bytes.len() > CONFIG_LIMIT {
        return None;
    }
    String::from_utf8(bytes.to_vec()).ok()
}

/// Write a message into the host's buffer: the in/out-length pattern.
fn write_error(buf: *mut c_char, len: usize, message: &str) {
    if buf.is_null() || len == 0 {
        return;
    }
    let bytes = message.as_bytes();
    let fit = bytes.len().min(len - 1);
    // SAFETY: the host lends `len` writable bytes for the call; the
    // fit above keeps the copy and the NUL inside them.
    #[expect(unsafe_code)]
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, fit);
        *buf.add(fit) = 0;
    }
}

/// Map an io error to the code table: the kinds the facade reports by
/// name, the raw errno (negated, as the table documents) when the OS
/// had one, generic otherwise.
fn errno_of(error: &std::io::Error) -> c_int {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => VFAWN_ERR_ALREADY_RUNNING,
        std::io::ErrorKind::Unsupported => VFAWN_ERR_UNSUPPORTED,
        _ => match error.raw_os_error() {
            Some(errno) if errno > 0 => -errno,
            _ => VFAWN_ERR_INVALID_CONFIG,
        },
    }
}

// --- The nine-function face ---------------------------------------------

/// The ABI version this library speaks.
#[expect(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn vfawn_version() -> u32 {
    VFAWN_ABI_VERSION
}

/// Parse and validate a configuration document without creating
/// anything.
///
/// # Safety
///
/// `json` must be a NUL-terminated string valid for the call; `err`
/// must be writable for `err_len` bytes when non-null.
#[expect(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfawn_config_validate(
    json: *const c_char,
    err: *mut c_char,
    err_len: usize,
) -> c_int {
    boundary(AssertUnwindSafe(|| match parse_config(json) {
        Ok(()) => VFAWN_OK,
        Err(message) => {
            write_error(err, err_len, &message);
            VFAWN_ERR_INVALID_CONFIG
        }
    }))
    .unwrap_or(VFAWN_ERR_PANIC)
}

use std::panic::AssertUnwindSafe;

/// Parse, validate, and say why not, in one shape.
fn parse_config(json: *const c_char) -> Result<(), String> {
    let json = borrowed_json(json)
        .ok_or_else(|| "configuration must be valid UTF-8 under 1 MiB".to_string())?;
    let config =
        serde_json::from_str::<vfawn_core::VfawnConfig>(&json).map_err(|e| e.to_string())?;
    config.validate().map_err(|e| e.to_string())
}

/// Create an instance from a configuration document. The instance is
/// constructed, not started; [`vfawn_instance_start`] brings it up.
/// A null handle means failure, with the reason in the error buffer.
///
/// # Safety
///
/// `json` must be a NUL-terminated string valid for the call; `err`
/// must be writable for `err_len` bytes when non-null.
#[expect(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfawn_instance_create(
    json: *const c_char,
    err: *mut c_char,
    err_len: usize,
) -> vfawn_instance_t {
    let outcome = boundary(AssertUnwindSafe(|| {
        let config = match borrowed_json(json)
            .ok_or_else(|| "configuration must be valid UTF-8 under 1 MiB".to_string())
            .and_then(|json| {
                serde_json::from_str::<vfawn_core::VfawnConfig>(&json).map_err(|e| e.to_string())
            })
            .and_then(|config| {
                config
                    .validate()
                    .map_err(|e| e.to_string())
                    .map(|()| config)
            }) {
            Ok(config) => config,
            Err(message) => {
                write_error(err, err_len, &message);
                return NULL_HANDLE;
            }
        };
        // Construction needs a handler; the relay stands in until the
        // host's vtable replaces it at start.
        match Instance::new(config, Arc::new(RelayHandler::new(None)))
            .map_err(|e| e.to_string())
            .and_then(insert_instance)
        {
            Ok(handle) => handle,
            Err(message) => {
                write_error(err, err_len, &message);
                NULL_HANDLE
            }
        }
    }));
    match outcome {
        Ok(handle) => handle,
        Err(_) => {
            write_error(
                err,
                err_len,
                "a panic crossed the boundary and was contained",
            );
            NULL_HANDLE
        }
    }
}

/// Place a constructed instance in the table; the handle on success.
fn insert_instance(instance: Instance) -> Result<vfawn_instance_t, String> {
    let mut guard = TABLE
        .lock()
        .map_err(|_| "the handle table lock is poisoned".to_string())?;
    let table = guard.get_or_insert_with(|| Table {
        slots: Vec::new(),
        next_generation: 1,
    });
    let generation = table.next_generation;
    table.next_generation = table.next_generation.wrapping_add(1).max(1);
    let body = Arc::new(SlotBody {
        instance: Mutex::new(instance),
        vtable: Mutex::new(None),
        error: Mutex::new(CString::new("").expect("empty message is valid C")),
        started: AtomicBool::new(false),
    });
    let index = match table.slots.iter().position(Option::is_none) {
        Some(index) => {
            table.slots[index] = Some(SlotEntry { generation, body });
            index
        }
        None => {
            table.slots.push(Some(SlotEntry { generation, body }));
            table.slots.len() - 1
        }
    };
    Ok(vfawn_instance_t {
        index: index as u32,
        generation,
    })
}

/// Set the host's callback vtable. Only before the first start; the
/// memory behind the vtable stays the host's and must outlive the
/// instance.
///
/// # Safety
///
/// `vtable` must point at readable memory of at least the size its
/// first field declares, for the instance's lifetime.
#[expect(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfawn_set_handler(
    handle: vfawn_instance_t,
    vtable: *const vfawn_handler_vtable_t,
) -> c_int {
    boundary(AssertUnwindSafe(|| {
        // SAFETY: the host's vtable contract is documented above.
        #[expect(unsafe_code)]
        let vtable = unsafe { VtableRef::from_raw(vtable) };
        with_body(handle, |body| {
            if body.started.load(AtomicOrdering::Acquire) {
                return Err(VFAWN_ERR_ALREADY_RUNNING);
            }
            match body.vtable.lock() {
                Ok(mut cell) => {
                    *cell = vtable;
                    Ok(())
                }
                Err(_) => Err(VFAWN_ERR_PANIC),
            }
        })
        .map(|()| VFAWN_OK)
        .unwrap_or_else(|code| code)
    }))
    .unwrap_or(VFAWN_ERR_PANIC)
}

/// Start the instance: device up, capture installed, sessions flow.
///
/// # Safety
///
/// The handle must come from [`vfawn_instance_create`] and not have
/// been destroyed; `err` must be writable for `err_len` bytes when
/// non-null.
#[expect(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfawn_instance_start(
    handle: vfawn_instance_t,
    err: *mut c_char,
    err_len: usize,
) -> c_int {
    let outcome = boundary(AssertUnwindSafe(|| {
        with_body(handle, |body| {
            let handler: Arc<dyn SessionHandler> = match body.vtable.lock() {
                Ok(cell) => match cell.as_ref() {
                    Some(vtable) => Arc::new(HostJudge(VtableRef {
                        judge: vtable.judge,
                        ctx: vtable.ctx,
                    })),
                    None => Arc::new(RelayHandler::new(None)),
                },
                Err(_) => return Err(VFAWN_ERR_PANIC),
            };
            let mut instance = match body.instance.lock() {
                Ok(instance) => instance,
                Err(_) => return Err(VFAWN_ERR_PANIC),
            };
            match instance.start(handler) {
                Ok(()) => {
                    body.started.store(true, AtomicOrdering::Release);
                    Ok(())
                }
                Err(e) => {
                    remember_error(body, &e.to_string());
                    Err(errno_of(&e))
                }
            }
        })
    }));
    match outcome {
        Ok(Ok(())) => VFAWN_OK,
        Ok(Err(code)) => code,
        Err(_) => {
            write_error(
                err,
                err_len,
                "a panic crossed the boundary and was contained",
            );
            VFAWN_ERR_PANIC
        }
    }
}

/// The instance's counters, by value.
///
/// # Safety
///
/// `stats` must be writable for the call, or null to just probe the
/// handle.
#[expect(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfawn_instance_stats(
    handle: vfawn_instance_t,
    stats: *mut vfawn_stats_t,
) -> c_int {
    boundary(AssertUnwindSafe(|| {
        with_body(handle, |body| {
            let instance = match body.instance.lock() {
                Ok(instance) => instance,
                Err(_) => return Err(VFAWN_ERR_PANIC),
            };
            let StatsSnapshot {
                sessions_total,
                bytes_forward,
                bytes_reverse,
                panics_contained,
            } = instance.stats();
            // SAFETY: the host lends the struct for the call.
            #[expect(unsafe_code)]
            if !stats.is_null() {
                unsafe {
                    *stats = vfawn_stats_t {
                        sessions_total,
                        bytes_forward,
                        bytes_reverse,
                        panics_contained,
                    };
                }
            }
            Ok(())
        })
        .map(|()| VFAWN_OK)
        .unwrap_or_else(|code| code)
    }))
    .unwrap_or(VFAWN_ERR_PANIC)
}

/// Hot-reconfigure the routes; a field that needs a restart answers
/// [`VFAWN_ERR_NEEDS_RESTART`] with the field named in the buffer.
///
/// # Safety
///
/// `json` must be a NUL-terminated string valid for the call; `err`
/// must be writable for `err_len` bytes when non-null.
#[expect(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfawn_instance_apply_config(
    handle: vfawn_instance_t,
    json: *const c_char,
    err: *mut c_char,
    err_len: usize,
) -> c_int {
    boundary(AssertUnwindSafe(|| {
        let config = match borrowed_json(json)
            .ok_or_else(|| "configuration must be valid UTF-8 under 1 MiB".to_string())
            .and_then(|json| {
                serde_json::from_str::<vfawn_core::VfawnConfig>(&json).map_err(|e| e.to_string())
            }) {
            Ok(config) => config,
            Err(message) => {
                write_error(err, err_len, &message);
                return VFAWN_ERR_INVALID_CONFIG;
            }
        };
        with_body(handle, |body| {
            let mut instance = match body.instance.lock() {
                Ok(instance) => instance,
                Err(_) => return Err(VFAWN_ERR_PANIC),
            };
            match instance.apply_config(&config) {
                Ok(()) => Ok(()),
                Err(e) => {
                    remember_error(body, &e.to_string());
                    Err(match e {
                        ApplyError::NeedsRestart(_) => VFAWN_ERR_NEEDS_RESTART,
                        ApplyError::NoRouteEngine => VFAWN_ERR_NOT_RUNNING,
                        ApplyError::Reconcile(_) => VFAWN_ERR_INVALID_CONFIG,
                    })
                }
            }
        })
        .map(|()| VFAWN_OK)
        .unwrap_or_else(|code| code)
    }))
    .unwrap_or(VFAWN_ERR_PANIC)
}

/// Stop the instance: sessions drain, the capture leaves, the device
/// closes. Idempotent.
///
/// # Safety
///
/// The handle must come from [`vfawn_instance_create`].
#[expect(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfawn_instance_shutdown(handle: vfawn_instance_t) -> c_int {
    boundary(AssertUnwindSafe(|| {
        with_body(handle, |body| {
            let mut instance = match body.instance.lock() {
                Ok(instance) => instance,
                Err(_) => return Err(VFAWN_ERR_PANIC),
            };
            match instance.shutdown() {
                Ok(()) => {
                    body.started.store(false, AtomicOrdering::Release);
                    Ok(())
                }
                Err(e) => {
                    remember_error(body, &e.to_string());
                    Err(errno_of(&e))
                }
            }
        })
        .map(|()| VFAWN_OK)
        .unwrap_or_else(|code| code)
    }))
    .unwrap_or(VFAWN_ERR_PANIC)
}

/// Destroy the instance and free its slot. The handle is dead after
/// this call; passing it again answers [`VFAWN_ERR_BAD_HANDLE`].
/// Idempotent and null-tolerant.
///
/// # Safety
///
/// The handle must come from [`vfawn_instance_create`], and no other
/// thread may be inside a call on it.
#[expect(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfawn_instance_destroy(handle: vfawn_instance_t) {
    if handle == NULL_HANDLE {
        return;
    }
    let _ = boundary(AssertUnwindSafe(|| {
        let Ok(mut guard) = TABLE.lock() else {
            return;
        };
        let Some(table) = guard.as_mut() else {
            return;
        };
        if let Some(slot) = table.slots.get_mut(handle.index as usize)
            && slot
                .as_ref()
                .is_some_and(|entry| entry.generation == handle.generation)
        {
            *slot = None;
        }
    }));
}

/// The instance's last error message, into the host's buffer with the
/// in/out-length pattern.
///
/// # Safety
///
/// `buf` must be writable for `len` bytes when non-null.
#[expect(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfawn_last_error_message(
    handle: vfawn_instance_t,
    buf: *mut c_char,
    len: usize,
) -> c_int {
    match with_body(handle, |body| match body.error.lock() {
        Ok(message) => {
            write_error(buf, len, &message.to_string_lossy());
            Ok(())
        }
        Err(_) => Err(VFAWN_ERR_PANIC),
    }) {
        Ok(()) => VFAWN_OK,
        Err(code) => code,
    }
}
