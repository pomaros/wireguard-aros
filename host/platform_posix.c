/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/* The four functions the WireGuard core asks of its platform, for a POSIX host. */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/random.h>
#include <time.h>

#include "wireguard-platform.h"

/* Tests add to this to move the clock forward. */
uint32_t wg_test_clock_offset_ms;

uint32_t wireguard_sys_now(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    /* Start well above zero: the core reads a zero timestamp as "never". */
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000) + 100000u + wg_test_clock_offset_ms;
}

void wireguard_random_bytes(void *bytes, size_t size) {
    uint8_t *p = bytes;

    while (size > 0) {
        size_t n = size > 256 ? 256 : size;
        if (getentropy(p, n) != 0) {
            abort();
        }
        p += n;
        size -= n;
    }
}

void wireguard_tai64n_now(uint8_t *output) {
    struct timespec ts;
    uint64_t seconds;
    uint32_t nanos;

    clock_gettime(CLOCK_REALTIME, &ts);
    seconds = 0x400000000000000aULL + (uint64_t)ts.tv_sec;
    nanos = (uint32_t)ts.tv_nsec;
    for (int i = 0; i < 8; i++) {
        output[i] = (uint8_t)(seconds >> (56 - 8 * i));
    }
    for (int i = 0; i < 4; i++) {
        output[8 + i] = (uint8_t)(nanos >> (24 - 8 * i));
    }
}

bool wireguard_is_under_load(void) {
    return false;
}
