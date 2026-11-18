/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
#include "wg_config.h"

#include <string.h>

#include "crypto.h"
#include "wireguard.h"

static void set_error(char *error, size_t error_len, int line, const char *what) {
    static const char prefix[] = "line ";
    char digits[12];
    int n = 0;
    size_t pos = 0;

    if (!error || error_len == 0) {
        return;
    }
    do {
        digits[n++] = (char)('0' + line % 10);
        line /= 10;
    } while (line > 0 && n < (int)sizeof(digits));
    for (size_t i = 0; prefix[i] && pos + 1 < error_len; i++) {
        error[pos++] = prefix[i];
    }
    while (n > 0 && pos + 1 < error_len) {
        error[pos++] = digits[--n];
    }
    if (pos + 2 < error_len) {
        error[pos++] = ':';
        error[pos++] = ' ';
    }
    for (size_t i = 0; what[i] && pos + 1 < error_len; i++) {
        error[pos++] = what[i];
    }
    error[pos] = 0;
}

static char lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

static bool key_is(const char *key, const char *name) {
    while (*key && *name) {
        if (lower(*key++) != lower(*name++)) {
            return false;
        }
    }
    return *key == 0 && *name == 0;
}

static char *trim(char *s) {
    char *end;

    while (*s == ' ' || *s == '\t') {
        s++;
    }
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) {
        *--end = 0;
    }
    return s;
}

static bool parse_uint(const char *s, unsigned long max, unsigned long *out) {
    unsigned long v = 0;

    if (!*s) {
        return false;
    }
    for (; *s; s++) {
        if (*s < '0' || *s > '9') {
            return false;
        }
        v = v * 10 + (unsigned long)(*s - '0');
        if (v > max) {
            return false;
        }
    }
    *out = v;
    return true;
}

bool wg_parse_ipv4(const char *s, uint32_t *out) {
    uint8_t b[4];

    for (int i = 0; i < 4; i++) {
        unsigned v = 0;
        int digits = 0;
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (unsigned)(*s++ - '0');
            if (++digits > 3 || v > 255) {
                return false;
            }
        }
        if (digits == 0) {
            return false;
        }
        b[i] = (uint8_t)v;
        if (i < 3) {
            if (*s++ != '.') {
                return false;
            }
        }
    }
    if (*s) {
        return false;
    }
    memcpy(out, b, 4);
    return true;
}

static uint32_t prefix_mask(unsigned long bits) {
    uint8_t b[4] = {0, 0, 0, 0};
    uint32_t mask;

    for (unsigned long i = 0; i < bits; i++) {
        b[i / 8] |= (uint8_t)(0x80 >> (i % 8));
    }
    memcpy(&mask, b, 4);
    return mask;
}

/* "a.b.c.d" or "a.b.c.d/n". default_bits applies without "/n". */
static bool parse_cidr(char *s, unsigned long default_bits, uint32_t *ip, uint32_t *mask) {
    unsigned long bits = default_bits;
    char *slash = strchr(s, '/');

    if (slash) {
        *slash = 0;
        if (!parse_uint(slash + 1, 32, &bits)) {
            return false;
        }
    }
    if (!wg_parse_ipv4(s, ip)) {
        return false;
    }
    *mask = prefix_mask(bits);
    return true;
}

static bool parse_key(const char *s, uint8_t *out) {
    uint8_t buf[33];
    size_t len = sizeof(buf);
    bool ok = wireguard_base64_decode(s, buf, &len) && len == 32;

    if (ok) {
        memcpy(out, buf, 32);
    }
    crypto_zero(buf, sizeof(buf));
    return ok;
}

/* Calls each comma-separated item of value, trimmed, with fn. */
typedef bool (*item_fn)(char *item, struct wg_config *cfg);

static bool each_item(char *value, struct wg_config *cfg, item_fn fn) {
    while (value) {
        char *comma = strchr(value, ',');
        if (comma) {
            *comma = 0;
        }
        char *item = trim(value);
        if (*item && !fn(item, cfg)) {
            return false;
        }
        value = comma ? comma + 1 : NULL;
    }
    return true;
}

static bool item_address(char *item, struct wg_config *cfg) {
    if (strchr(item, ':')) {
        cfg->skipped_ipv6++;
        return true;
    }
    if (cfg->address != 0) {
        return true; /* the first IPv4 address is the tunnel's */
    }
    return parse_cidr(item, 32, &cfg->address, &cfg->netmask);
}

static bool item_dns(char *item, struct wg_config *cfg) {
    uint32_t ip;

    if (strchr(item, ':')) {
        cfg->skipped_ipv6++;
        return true;
    }
    if (!wg_parse_ipv4(item, &ip)) {
        return true; /* a search domain */
    }
    if (cfg->dns_count < WG_CONFIG_MAX_DNS) {
        cfg->dns[cfg->dns_count++] = ip;
    }
    return true;
}

static bool item_allowed(char *item, struct wg_config *cfg) {
    if (strchr(item, ':')) {
        cfg->skipped_ipv6++;
        return true;
    }
    if (cfg->allowed_count >= WG_CONFIG_MAX_ALLOWED) {
        return false;
    }
    uint32_t ip, mask;
    if (!parse_cidr(item, 32, &ip, &mask)) {
        return false;
    }
    cfg->allowed[cfg->allowed_count].ip = ip & mask;
    cfg->allowed[cfg->allowed_count].mask = mask;
    cfg->allowed_count++;
    return true;
}

static bool parse_endpoint(char *value, struct wg_config *cfg) {
    unsigned long port;
    char *colon;

    if (value[0] == '[') {
        return false; /* an IPv6 endpoint */
    }
    colon = strrchr(value, ':');
    if (!colon || colon == value || !parse_uint(colon + 1, 65535, &port) || port == 0) {
        return false;
    }
    *colon = 0;
    if (strlen(value) >= sizeof(cfg->endpoint_host)) {
        return false;
    }
    strcpy(cfg->endpoint_host, value);
    cfg->endpoint_port = (uint16_t)port;
    return true;
}

bool wg_config_parse(const char *text, size_t len, struct wg_config *cfg, char *error, size_t error_len) {
    enum { NONE, INTERFACE, PEER, OTHER_PEER } section = NONE;
    char line[512];
    size_t pos = 0;
    int line_no = 0;
    int peers = 0;
    bool have_private = false, have_public = false;
    bool ok = true;

    memset(cfg, 0, sizeof(*cfg));

    while (ok && pos <= len) {
        size_t n = 0;
        bool too_long = false;

        if (pos == len) {
            break;
        }
        while (pos < len && text[pos] != '\n') {
            if (n + 1 < sizeof(line)) {
                line[n++] = text[pos];
            } else {
                too_long = true;
            }
            pos++;
        }
        pos++; /* the newline */
        line[n] = 0;
        line_no++;

        char *hash = strchr(line, '#');
        if (hash) {
            *hash = 0;
        }
        char *s = trim(line);
        if (!*s) {
            continue;
        }
        if (too_long) {
            set_error(error, error_len, line_no, "line too long");
            ok = false;
            break;
        }
        if (*s == '[') {
            if (key_is(s, "[Interface]")) {
                section = INTERFACE;
            } else if (key_is(s, "[Peer]")) {
                section = (++peers == 1) ? PEER : OTHER_PEER;
            } else {
                set_error(error, error_len, line_no, "unknown section");
                ok = false;
            }
            continue;
        }
        char *eq = strchr(s, '=');
        if (!eq) {
            set_error(error, error_len, line_no, "expected key = value");
            ok = false;
            break;
        }
        *eq = 0;
        char *key = trim(s);
        char *value = trim(eq + 1);
        unsigned long number;
        const char *bad = NULL;

        if (section == INTERFACE) {
            if (key_is(key, "PrivateKey")) {
                if (parse_key(value, cfg->private_key)) {
                    have_private = true;
                } else {
                    bad = "PrivateKey is not a 32-byte base64 key";
                }
            } else if (key_is(key, "Address")) {
                if (!each_item(value, cfg, item_address)) {
                    bad = "bad Address";
                }
            } else if (key_is(key, "DNS")) {
                each_item(value, cfg, item_dns);
            } else if (key_is(key, "ListenPort")) {
                if (parse_uint(value, 65535, &number)) {
                    cfg->listen_port = (uint16_t)number;
                } else {
                    bad = "bad ListenPort";
                }
            } else if (key_is(key, "MTU")) {
                if (parse_uint(value, 65535, &number) && number >= 576) {
                    cfg->mtu = (uint16_t)number;
                } else {
                    bad = "bad MTU";
                }
            }
            /* Table, PreUp, PostUp and the like belong to wg-quick and are left out. */
        } else if (section == PEER) {
            if (key_is(key, "PublicKey")) {
                if (parse_key(value, cfg->public_key)) {
                    have_public = true;
                } else {
                    bad = "PublicKey is not a 32-byte base64 key";
                }
            } else if (key_is(key, "PresharedKey")) {
                if (parse_key(value, cfg->preshared_key)) {
                    cfg->has_preshared_key = true;
                } else {
                    bad = "PresharedKey is not a 32-byte base64 key";
                }
            } else if (key_is(key, "AllowedIPs")) {
                if (!each_item(value, cfg, item_allowed)) {
                    bad = "bad AllowedIPs, or more than four IPv4 prefixes";
                }
            } else if (key_is(key, "Endpoint")) {
                if (!parse_endpoint(value, cfg)) {
                    bad = "Endpoint must be host:port with an IPv4 address or a name";
                }
            } else if (key_is(key, "PersistentKeepalive")) {
                if (key_is(value, "off")) {
                    cfg->keepalive = 0;
                } else if (parse_uint(value, 65535, &number)) {
                    cfg->keepalive = (uint16_t)number;
                } else {
                    bad = "bad PersistentKeepalive";
                }
            }
        } else if (section == NONE) {
            bad = "value before the first section";
        }
        /* Clear the line buffer: it may hold a key. */
        crypto_zero(line, sizeof(line));
        if (bad) {
            set_error(error, error_len, line_no, bad);
            ok = false;
        }
    }

    if (ok && peers > 1) {
        set_error(error, error_len, line_no, "more than one [Peer]: one peer is supported");
        ok = false;
    }
    if (ok && !have_private) {
        set_error(error, error_len, line_no, "no PrivateKey in [Interface]");
        ok = false;
    }
    if (ok && !have_public) {
        set_error(error, error_len, line_no, "no PublicKey in [Peer]");
        ok = false;
    }
    if (ok && cfg->address == 0) {
        set_error(error, error_len, line_no, "no IPv4 Address in [Interface]");
        ok = false;
    }
    if (ok && cfg->allowed_count == 0) {
        set_error(error, error_len, line_no, "no IPv4 prefix in AllowedIPs");
        ok = false;
    }
    if (!ok) {
        wg_config_wipe(cfg);
    }
    return ok;
}

void wg_config_wipe(struct wg_config *cfg) {
    crypto_zero(cfg, sizeof(*cfg));
}
