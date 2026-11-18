/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * The vendored WireGuard core names four lwIP headers for a handful of
 * types. This file gives it those types, so the core builds unmodified
 * without lwIP.
 */
#ifndef WG_COMPAT_LWIP_TYPES_H
#define WG_COMPAT_LWIP_TYPES_H

#include <stdint.h>

typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;

/* An IPv4 address in network byte order. */
typedef struct wg_ip4_addr {
    uint32_t addr;
} ip_addr_t;

struct netif;
struct udp_pcb;

#endif
