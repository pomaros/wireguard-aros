/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * Two tunnel engines joined by an in-memory wire. Checks the handshake, data
 * in both directions, and that a forged, a replayed and a wrongly sourced
 * packet are each dropped and counted. Needs no network.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "wg_config.h"
#include "wg_tunnel.h"

extern uint32_t wg_test_clock_offset_ms;

#define QUEUE 64
struct datagram {
    uint8_t data[1600];
    size_t len;
};
struct endpoint {
    struct wg_tunnel tunnel;
    struct endpoint *other;
    uint32_t ip;               /* outer address, network order */
    uint16_t port;
    struct datagram inbox[QUEUE];
    int head, tail;
    uint8_t delivered[1600];   /* last inner packet handed up */
    size_t delivered_len;
    int delivered_count;
    /* Fault injection on what this endpoint sends. */
    int corrupt_next;          /* flip one byte of the next transport packet */
    int duplicate_next;        /* deliver the next transport packet twice */
    int drop_all;
};

static int failures;
#define CHECK(cond, name) do { if (cond) { printf("PASS %s\n", name); } else { printf("FAIL %s\n", name); failures++; } } while (0)

static int udp_send(void *ctx, const uint8_t *data, size_t len, uint32_t ip, uint16_t port) {
    struct endpoint *self = ctx;
    struct endpoint *to = self->other;
    int copies = 1;

    (void)ip; (void)port;
    if (self->drop_all) {
        return 0;
    }
    if (data[0] == MESSAGE_TRANSPORT_DATA && len > 32 && self->duplicate_next) {
        self->duplicate_next = 0;
        copies = 2;
    }
    for (int c = 0; c < copies; c++) {
        struct datagram *d = &to->inbox[to->tail % QUEUE];
        memcpy(d->data, data, len);
        d->len = len;
        if (data[0] == MESSAGE_TRANSPORT_DATA && len > 32 && self->corrupt_next) {
            self->corrupt_next = 0;
            d->data[20] ^= 0x01;
        }
        to->tail++;
    }
    return 0;
}

static void ip_input(void *ctx, const uint8_t *packet, size_t len) {
    struct endpoint *self = ctx;

    memcpy(self->delivered, packet, len);
    self->delivered_len = len;
    self->delivered_count++;
}

static void pump(struct endpoint *a, struct endpoint *b) {
    int moved;

    do {
        moved = 0;
        for (struct endpoint *e = a; e; e = (e == a) ? b : NULL) {
            while (e->head < e->tail) {
                struct datagram *d = &e->inbox[e->head++ % QUEUE];
                wg_tunnel_udp_input(&e->tunnel, d->data, d->len, e->other->ip, e->other->port);
                moved = 1;
            }
        }
    } while (moved);
}

static void tick(struct endpoint *a, struct endpoint *b, int times) {
    for (int i = 0; i < times; i++) {
        wg_test_clock_offset_ms += WG_TUNNEL_TICK_MSECS;
        wg_tunnel_tick(&a->tunnel);
        wg_tunnel_tick(&b->tunnel);
        pump(a, b);
    }
}

static size_t make_packet(uint8_t *p, const char *src, const char *dst, size_t payload) {
    uint32_t s, d;
    size_t len = 20 + payload;

    wg_parse_ipv4(src, &s);
    wg_parse_ipv4(dst, &d);
    memset(p, 0, len);
    p[0] = 0x45;
    p[2] = (uint8_t)(len >> 8);
    p[3] = (uint8_t)len;
    p[8] = 64;
    p[9] = 17;
    memcpy(p + 12, &s, 4);
    memcpy(p + 16, &d, 4);
    for (size_t i = 0; i < payload; i++) {
        p[20 + i] = (uint8_t)(i * 7 + 1);
    }
    return len;
}

static void make_keys(uint8_t *priv, uint8_t *pub) {
    static struct wireguard_device scratch;

    wireguard_random_bytes(priv, 32);
    priv[0] &= 248; priv[31] = (uint8_t)((priv[31] & 127) | 64);
    wireguard_device_init(&scratch, priv);
    memcpy(pub, scratch.public_key, 32);
}

static struct endpoint a, b, c;

int main(void) {
    static const struct wg_tunnel_ops ops = {udp_send, ip_input};
    uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32], psk[32], other_priv[32], other_pub[32];
    uint8_t packet[1600];
    uint8_t index;
    uint32_t ip, mask;
    size_t len;

    wireguard_init();
    make_keys(a_priv, a_pub);
    make_keys(b_priv, b_pub);
    make_keys(other_priv, other_pub);
    wireguard_random_bytes(psk, 32);

    a.other = &b; b.other = &a;
    wg_parse_ipv4("192.0.2.1", &a.ip); a.port = 40000;
    wg_parse_ipv4("192.0.2.2", &b.ip); b.port = 51820;

    CHECK(wg_tunnel_init(&a.tunnel, a_priv, &ops, &a) == WG_OK, "init initiator");
    CHECK(wg_tunnel_init(&b.tunnel, b_priv, &ops, &b) == WG_OK, "init responder");

    /* A reaches 10.0.0.0/24 through B; B accepts only 10.9.0.2 from A. */
    CHECK(wg_tunnel_add_peer(&a.tunnel, b_pub, psk, b.ip, b.port, 25, &index) == WG_OK, "initiator adds peer");
    wg_parse_ipv4("10.0.0.0", &ip); wg_parse_ipv4("255.255.255.0", &mask);
    wg_tunnel_allow(&a.tunnel, index, ip, mask);
    CHECK(wg_tunnel_add_peer(&b.tunnel, a_pub, psk, 0, 0, 0, &index) == WG_OK, "responder adds peer");
    wg_parse_ipv4("10.9.0.2", &ip); wg_parse_ipv4("255.255.255.255", &mask);
    wg_tunnel_allow(&b.tunnel, index, ip, mask);

    len = make_packet(packet, "10.9.0.2", "10.0.0.7", 100);
    CHECK(wg_tunnel_output(&a.tunnel, packet, len) == WG_ERR_NO_SESSION, "no session before the handshake");
    CHECK(!wg_tunnel_is_up(&a.tunnel), "tunnel down before the handshake");

    wg_tunnel_connect(&a.tunnel, 0);
    tick(&a, &b, 2);
    CHECK(wg_tunnel_is_up(&a.tunnel) && wg_tunnel_is_up(&b.tunnel), "handshake completes on both sides");
    CHECK(a.tunnel.stats.handshakes_sent == 1, "one initiation sent");

    CHECK(wg_tunnel_output(&a.tunnel, packet, len) == WG_OK, "initiator sends data");
    pump(&a, &b);
    CHECK(b.delivered_count == 1 && b.delivered_len == len && memcmp(b.delivered, packet, len) == 0,
          "responder receives the same bytes");

    len = make_packet(packet, "10.0.0.7", "10.9.0.2", 1380);
    CHECK(wg_tunnel_output(&b.tunnel, packet, len) == WG_OK, "responder sends a 1400-byte packet back");
    pump(&a, &b);
    CHECK(a.delivered_count == 1 && a.delivered_len == len && memcmp(a.delivered, packet, len) == 0,
          "initiator receives the same bytes");

    /* Controls: each of these must be dropped and counted. */
    len = make_packet(packet, "10.9.0.2", "10.0.0.7", 64);
    a.corrupt_next = 1;
    wg_tunnel_output(&a.tunnel, packet, len);
    pump(&a, &b);
    CHECK(b.delivered_count == 1 && b.tunnel.stats.rx_bad_auth == 1, "a packet with one flipped byte is dropped");

    a.duplicate_next = 1;
    wg_tunnel_output(&a.tunnel, packet, len);
    pump(&a, &b);
    CHECK(b.delivered_count == 2 && b.tunnel.stats.rx_replayed == 1, "a replayed packet is delivered once");

    len = make_packet(packet, "10.9.0.99", "10.0.0.7", 64);
    wg_tunnel_output(&a.tunnel, packet, len);
    pump(&a, &b);
    CHECK(b.delivered_count == 2 && b.tunnel.stats.rx_bad_source == 1, "a source outside AllowedIPs is dropped");

    len = make_packet(packet, "10.9.0.2", "172.16.0.1", 64);
    CHECK(wg_tunnel_output(&a.tunnel, packet, len) == WG_ERR_NO_ROUTE, "a destination outside AllowedIPs has no route");

    /* Rekey: past REKEY_AFTER_TIME the initiator starts a new handshake on its next packet. */
    wg_test_clock_offset_ms += (REKEY_AFTER_TIME + 2) * 1000;
    len = make_packet(packet, "10.9.0.2", "10.0.0.7", 64);
    wg_tunnel_output(&a.tunnel, packet, len);
    pump(&a, &b);
    tick(&a, &b, 3);
    CHECK(a.tunnel.stats.handshakes_completed == 2, "the session is rekeyed after two minutes");
    wg_tunnel_output(&a.tunnel, packet, len);
    pump(&a, &b);
    CHECK(b.delivered_count == 4, "data flows on the new session");

    /* Keepalive: silence for the interval makes the initiator send an empty packet. */
    uint32_t before = b.tunnel.device.peers[0].last_rx;
    tick(&a, &b, (25 * 1000) / WG_TUNNEL_TICK_MSECS + 3);
    CHECK(b.tunnel.device.peers[0].last_rx != before && b.delivered_count == 4, "a keepalive arrives and carries no packet");

    /* Expiry: with the wire cut, no session survives past the reject time. */
    a.drop_all = 1; b.drop_all = 1;
    tick(&a, &b, ((REJECT_AFTER_TIME + 10) * 1000) / WG_TUNNEL_TICK_MSECS);
    CHECK(!wg_tunnel_is_up(&a.tunnel), "keys are destroyed after three minutes without a handshake");

    /* A peer with another static key gets no session. */
    c.other = &b; c.ip = a.ip; c.port = 40001;
    b.other = &c;
    b.drop_all = 0;
    wg_tunnel_init(&c.tunnel, other_priv, &ops, &c);
    wg_tunnel_add_peer(&c.tunnel, b_pub, psk, b.ip, b.port, 0, &index);
    wg_tunnel_connect(&c.tunnel, 0);
    tick(&c, &b, 4);
    CHECK(!wg_tunnel_is_up(&c.tunnel) && c.tunnel.stats.handshakes_sent >= 1, "an unknown static key gets no session");

    /* Configuration parser. */
    static const char good[] =
        "[Interface]\n# Key for test\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Address = 10.2.0.2/32, 2a07:b944::2:2/128\nDNS = 10.2.0.1, 2a07:b944::2:1\n\n"
        "[Peer]\r\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 0.0.0.0/0, ::/0\n"
        "Endpoint = 198.51.100.7:51820\nPersistentKeepalive = 25\n";
    struct wg_config cfg;
    char error[96];
    uint32_t want;
    CHECK(wg_config_parse(good, sizeof(good) - 1, &cfg, error, sizeof(error)), "a dual-stack configuration parses");
    wg_parse_ipv4("10.2.0.2", &want);
    CHECK(cfg.address == want && cfg.netmask == 0xffffffffu && cfg.dns_count == 1 && cfg.allowed_count == 1 &&
          cfg.allowed[0].mask == 0 && cfg.endpoint_port == 51820 && cfg.keepalive == 25 && cfg.skipped_ipv6 == 3 &&
          strcmp(cfg.endpoint_host, "198.51.100.7") == 0, "its IPv4 values are kept and its three IPv6 values counted");
    static const char bad[] = "[Interface]\nPrivateKey = short\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = x\n";
    CHECK(!wg_config_parse(bad, sizeof(bad) - 1, &cfg, error, sizeof(error)) && strncmp(error, "line 2:", 7) == 0,
          "a short key is refused with its line number");
    static const char nopeer[] = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.2.0.2/32\n";
    CHECK(!wg_config_parse(nopeer, sizeof(nopeer) - 1, &cfg, error, sizeof(error)), "a configuration without a peer is refused");

    printf("test_tunnel: %s (%d failed)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
