/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * Reads a wg-quick style configuration: one [Interface] section and one
 * [Peer] section. IPv4 values are kept; IPv6 values are counted and skipped.
 */
#ifndef WG_CONFIG_H
#define WG_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WG_CONFIG_MAX_ALLOWED 4
#define WG_CONFIG_MAX_DNS 2
#define WG_CONFIG_HOST_LEN 128

struct wg_config {
    uint8_t private_key[32];
    uint8_t public_key[32];
    uint8_t preshared_key[32];
    bool has_preshared_key;

    uint32_t address;      /* network byte order */
    uint32_t netmask;      /* network byte order */
    uint32_t dns[WG_CONFIG_MAX_DNS];
    int dns_count;
    uint16_t listen_port;  /* 0 lets the system choose */
    uint16_t mtu;          /* 0 means the default */

    char endpoint_host[WG_CONFIG_HOST_LEN]; /* a dotted address or a name */
    uint16_t endpoint_port;
    uint16_t keepalive;

    struct {
        uint32_t ip, mask; /* network byte order */
    } allowed[WG_CONFIG_MAX_ALLOWED];
    int allowed_count;

    int skipped_ipv6;      /* IPv6 addresses, DNS servers and prefixes left out */
};

/*
 * Parses text (len bytes, need not be terminated). Returns true on success.
 * On failure, error receives a message naming the line. The key material in
 * cfg is the caller's to wipe with wg_config_wipe().
 */
bool wg_config_parse(const char *text, size_t len, struct wg_config *cfg, char *error, size_t error_len);
void wg_config_wipe(struct wg_config *cfg);

/* "a.b.c.d" to network byte order. Returns false when s is not a dotted IPv4 address. */
bool wg_parse_ipv4(const char *s, uint32_t *out);

#endif
