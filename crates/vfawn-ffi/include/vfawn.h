#ifndef VFAWN_H
#define VFAWN_H

/* Regenerate with VFAWN_REGEN_HEADER=1 cargo test -p vfawn-ffi; do not edit by hand. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * The ABI version this library speaks; bump on any breaking change.
 */
#define VFAWN_ABI_VERSION 1

#define VFAWN_OK 0

#define VFAWN_ERR_INVALID_CONFIG 1

#define VFAWN_ERR_ALREADY_RUNNING 2

#define VFAWN_ERR_NOT_RUNNING 3

#define VFAWN_ERR_UNSUPPORTED 4

#define VFAWN_ERR_BAD_HANDLE 5

#define VFAWN_ERR_BUFFER_TOO_SMALL 6

#define VFAWN_ERR_NEEDS_RESTART 7

#define VFAWN_ERR_PANIC 8

#define VFAWN_ERR_REENTRANT 9

/**
 * The running stack stopped on its own: its device went away (an
 * adapter disabled or removed outside this process). The instance
 * does not rebuild itself; shut it down and start a new one.
 */
#define VFAWN_ERR_DEVICE_LOST 10

#define VFAWN_VERDICT_ACCEPT 0

#define VFAWN_VERDICT_BYPASS 1

#define VFAWN_VERDICT_DROP 2

#define VFAWN_VERDICT_REJECT 3

/**
 * The handle: an index into the process-wide table paired with the
 * slot's generation. A destroyed slot's index recycles only with a
 * new generation, so a stale handle from an earlier life answers
 * [`VFAWN_ERR_BAD_HANDLE`], never a stranger.
 */
typedef struct vfawn_instance_t {
  /**
   * The table slot; zero only on the null handle.
   */
  uint32_t index;
  /**
   * The slot's life; a recycled index carries a new one.
   */
  uint32_t generation;
} vfawn_instance_t;

/**
 * The verdict callback. `flow_json` is a borrowed, NUL-terminated
 * JSON view of the flow (`{"source":"ip:port","destination":...,
 * "network":"tcp"}`) valid only for the call; copy what you keep.
 * The callback runs on a data-plane thread: it must not block and
 * must not reenter the ABI.
 */
typedef int (*vfawn_judge_fn)(void *ctx, const char *flow_json);

/**
 * The vtable, versioned by size: later fields may be appended, a
 * smaller vtable from an older host leaves them null.
 */
typedef struct vfawn_handler_vtable_t {
  /**
   * `sizeof` at the host's compile time.
   */
  uintptr_t size;
  /**
   * The host's own context, passed to every callback untouched.
   */
  void *ctx;
  /**
   * The flow judge; None accepts everything (the relay default).
   */
  vfawn_judge_fn judge_flow;
} vfawn_handler_vtable_t;

typedef struct vfawn_stats_t {
  uint64_t sessions_total;
  uint64_t bytes_forward;
  uint64_t bytes_reverse;
  uint64_t panics_contained;
} vfawn_stats_t;

/**
 * The null handle: what creation answers when it fails, and the
 * value C initializes its variables to.
 */
#define VFAWN_NULL_HANDLE (vfawn_instance_t){ .index = 0, .generation = 0 }

/**
 * The ABI version this library speaks.
 */
uint32_t vfawn_version(void);

/**
 * Parse and validate a configuration document without creating
 * anything.
 *
 * # Safety
 *
 * `json` must be a NUL-terminated string valid for the call; `err`
 * must be writable for `err_len` bytes when non-null.
 */
int vfawn_config_validate(const char *json, char *err, uintptr_t err_len);

/**
 * Create an instance from a configuration document. The instance is
 * constructed, not started; [`vfawn_instance_start`] brings it up.
 * A null handle means failure, with the reason in the error buffer.
 *
 * # Safety
 *
 * `json` must be a NUL-terminated string valid for the call; `err`
 * must be writable for `err_len` bytes when non-null.
 */
struct vfawn_instance_t vfawn_instance_create(const char *json, char *err, uintptr_t err_len);

/**
 * Set the host's callback vtable. Only before the first start; the
 * memory behind the vtable stays the host's and must outlive the
 * instance.
 *
 * # Safety
 *
 * `vtable` must point at readable memory of at least the size its
 * first field declares, for the instance's lifetime.
 */
int vfawn_set_handler(struct vfawn_instance_t handle, const struct vfawn_handler_vtable_t *vtable);

/**
 * Start the instance: device up, capture installed, sessions flow.
 *
 * # Safety
 *
 * The handle must come from [`vfawn_instance_create`] and not have
 * been destroyed; `err` must be writable for `err_len` bytes when
 * non-null.
 */
int vfawn_instance_start(struct vfawn_instance_t handle, char *err, uintptr_t err_len);

/**
 * The instance's counters, by value.
 *
 * # Safety
 *
 * `stats` must be writable for the call, or null to just probe the
 * handle.
 */
int vfawn_instance_stats(struct vfawn_instance_t handle, struct vfawn_stats_t *stats);

/**
 * Whether the running stack is still up. [`VFAWN_OK`] while it runs
 * (or before it was started); [`VFAWN_ERR_DEVICE_LOST`] once it stopped
 * on its own, with the reason in `err`. Polling this is how a host
 * learns to restart: as sing-tun's stack does, this one stops on a
 * lost device rather than rebuilding it.
 *
 * # Safety
 *
 * `err` must be writable for `err_len` bytes when non-null.
 */
int vfawn_instance_health(struct vfawn_instance_t handle, char *err, uintptr_t err_len);

/**
 * Hot-reconfigure the routes; a field that needs a restart answers
 * [`VFAWN_ERR_NEEDS_RESTART`] with the field named in the buffer.
 *
 * # Safety
 *
 * `json` must be a NUL-terminated string valid for the call; `err`
 * must be writable for `err_len` bytes when non-null.
 */
int vfawn_instance_apply_config(struct vfawn_instance_t handle,
                                const char *json,
                                char *err,
                                uintptr_t err_len);

/**
 * Stop the instance: sessions drain, the capture leaves, the device
 * closes. Idempotent.
 *
 * # Safety
 *
 * The handle must come from [`vfawn_instance_create`].
 */
int vfawn_instance_shutdown(struct vfawn_instance_t handle);

/**
 * Destroy the instance and free its slot. The handle is dead after
 * this call; passing it again answers [`VFAWN_ERR_BAD_HANDLE`].
 * Idempotent and null-tolerant.
 *
 * # Safety
 *
 * The handle must come from [`vfawn_instance_create`], and no other
 * thread may be inside a call on it.
 */
void vfawn_instance_destroy(struct vfawn_instance_t handle);

/**
 * The instance's last error message, into the host's buffer with the
 * in/out-length pattern.
 *
 * # Safety
 *
 * `buf` must be writable for `len` bytes when non-null.
 */
int vfawn_last_error_message(struct vfawn_instance_t handle, char *buf, uintptr_t len);

#endif  /* VFAWN_H */
