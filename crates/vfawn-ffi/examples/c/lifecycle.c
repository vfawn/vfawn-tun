/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors */

/*
 * The C host's whole lifecycle: validate, create, judge, start,
 * stats, hot-update, shutdown, destroy. One file, no framework, the
 * ABI is the framework.
 *
 *   cc lifecycle.c -I ../../include -L ../../../../target/debug \
 *      -lvfawn_ffi -o lifecycle && LD_LIBRARY_PATH=../../../../target/debug ./lifecycle
 *
 * MSVC, from the workspace root in a developer prompt: rustc names the
 * cdylib's import library vfawn_ffi.dll.lib, and the DLL must be on
 * PATH at run time.
 *
 *   cl /utf-8 /WX /I crates\vfawn-ffi\include crates\vfawn-ffi\examples\c\lifecycle.c ^
 *      /link /LIBPATH:target\debug vfawn_ffi.dll.lib /OUT:vfawn-lifecycle.exe
 *   set PATH=%CD%\target\debug;%PATH% && vfawn-lifecycle.exe
 */

#include <stdio.h>
#include <string.h>
#include "vfawn.h"

/* The host's judge: drop nothing, log what crosses. */
static int judge(void *ctx, const char *flow_json) {
    (void)ctx;
    printf("judge: %s\n", flow_json);
    return VFAWN_VERDICT_ACCEPT;
}

static int failures = 0;

static void check(int condition, const char *what) {
    if (condition) {
        printf("ok: %s\n", what);
    } else {
        printf("FAIL: %s\n", what);
        failures++;
    }
}

int main(void) {
    char err[256] = {0};

    check(vfawn_version() >= 1, "the ABI version is one or newer");

    const char *config =
        "{\"device\":{\"mtu\":1500,"
        "\"inet4_address\":[\"198.18.0.1/15\"]},"
        "\"route\":{\"auto_route\":false}}";
    check(vfawn_config_validate(config, err, sizeof err) == VFAWN_OK,
          "the sample configuration validates");

    /* Malformed documents must answer codes, not crashes. */
    check(vfawn_config_validate("{ not json", err, sizeof err) ==
              VFAWN_ERR_INVALID_CONFIG,
          "malformed JSON answers a code");
    check(vfawn_config_validate("{\"device\":{\"mtu\":-1}}", err, sizeof err) ==
              VFAWN_ERR_INVALID_CONFIG,
          "a negative MTU is refused");

    vfawn_instance_t instance = vfawn_instance_create(config, err, sizeof err);
    check(instance.generation != 0, "the instance was created");

    vfawn_handler_vtable_t vtable = {sizeof vtable, NULL, judge};
    check(vfawn_set_handler(instance, &vtable) == VFAWN_OK,
          "the judge vtable was accepted");

    /* The real start: device up (no capture, the config's route is
     * off), sessions flowing under the judge above. Privileges are
     * the platform's own rule for interface creation. */
    int started = vfawn_instance_start(instance, err, sizeof err);
    if (started == VFAWN_OK) {
        check(1, "the instance started");
    } else if (started < 0) {
        /* A negative code is a raw errno: the platform's own rule for
         * who may create interfaces. Privileged runs must pass the
         * whole lifecycle; unprivileged ones say so and skip the
         * started-only steps. */
        printf("skip: start needs privileges (errno %d)\n", -started);
    } else {
        check(0, "the instance started");
        printf("     %s\n", err);
    }

    check(vfawn_instance_stats(instance, NULL) == VFAWN_OK,
          "stats answer with a null out-pointer");

    if (started == VFAWN_OK) {
        check(vfawn_instance_apply_config(instance, config, err, sizeof err) ==
                  VFAWN_ERR_NOT_RUNNING,
              "apply with no capture reports the engine shape");
    }

    check(vfawn_instance_shutdown(instance) == VFAWN_OK, "shutdown is fine");
    check(vfawn_instance_shutdown(instance) == VFAWN_OK, "shutdown is idempotent");

    vfawn_instance_destroy(instance);
    check(vfawn_instance_stats(instance, NULL) == VFAWN_ERR_BAD_HANDLE,
          "a destroyed handle answers bad-handle");

    printf(failures == 0 ? "lifecycle: all green\n" : "lifecycle: FAILURES\n");
    return failures == 0 ? 0 : 1;
}
