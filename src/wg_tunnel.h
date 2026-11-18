/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026 John Knipper
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 *
 * A WireGuard tunnel engine with no network stack under it. The caller
 * supplies two functions, one that sends a UDP datagram and one that
 * receives a decrypted IP packet, and calls the engine with the outer
 * datagrams, the inner packets and a periodic tick. The peer state
 * machine follows wireguardif.c of wireguard-lwip.
 */
#ifndef WG_TUNNEL_H
#define WG_TUNNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wireguard.h"

#define WG_TUNNEL_TICK_MSECS 400
#define WG_TUNNEL_MTU 1420
#define WG_TUNNEL_MAX_PACKET 1500
/* Transport header, padding to 16 bytes and the authentication tag. */
#define WG_TUNNEL_OVERHEAD (16 + 15 + WIREGUARD_AUTHTAG_LEN)

enum wg_result {
    WG_OK = 0,
    WG_ERR_ARG = -1,
    WG_ERR_NO_ROUTE = -2,
    WG_ERR_NO_SESSION = -3,
    WG_ERR_TOO_BIG = -4,
    WG_ERR_SEND = -5,
};

struct wg_tunnel_ops {
    /* Send one UDP datagram to ip:port. ip is in network byte order, port in host order. Returns 0 on success. */
    int (*udp_send)(void *ctx, const uint8_t *data, size_t len, uint32_t ip, uint16_t port);
    /* Deliver one decrypted, source-checked IPv4 packet to the stack. */
    void (*ip_input)(void *ctx, const uint8_t *packet, size_t len);
};

struct wg_tunnel_stats {
    uint64_t tx_packets, tx_bytes;
    uint64_t rx_packets, rx_bytes;
    uint64_t rx_bad_auth;      /* transport packets whose tag did not verify */
    uint64_t rx_replayed;      /* authentic packets outside the replay window */
    uint64_t rx_bad_source;    /* inner source address outside AllowedIPs */
    uint64_t rx_malformed;     /* inner packet that is not a whole IPv4 packet */
    uint64_t tx_no_session;    /* packets dropped while no session exists */
    uint32_t handshakes_sent;
    uint32_t handshakes_completed;
};

struct wg_tunnel {
    struct wireguard_device device;
    struct wg_tunnel_ops ops;
    void *ctx;
    struct wg_tunnel_stats stats;
    uint8_t scratch[WG_TUNNEL_MAX_PACKET + WG_TUNNEL_OVERHEAD];
};

/* private_key is 32 raw bytes. */
int wg_tunnel_init(struct wg_tunnel *t, const uint8_t *private_key, const struct wg_tunnel_ops *ops, void *ctx);
void wg_tunnel_shutdown(struct wg_tunnel *t);

/*
 * Adds the peer. preshared_key may be NULL. endpoint_ip is in network byte
 * order and may be 0 for a peer that only answers. keepalive is in seconds,
 * 0 disables it.
 */
int wg_tunnel_add_peer(struct wg_tunnel *t, const uint8_t *public_key, const uint8_t *preshared_key,
                       uint32_t endpoint_ip, uint16_t endpoint_port, uint16_t keepalive, uint8_t *peer_index);
/* ip and mask in network byte order. */
int wg_tunnel_allow(struct wg_tunnel *t, uint8_t peer_index, uint32_t ip, uint32_t mask);
int wg_tunnel_connect(struct wg_tunnel *t, uint8_t peer_index);
int wg_tunnel_disconnect(struct wg_tunnel *t, uint8_t peer_index);
bool wg_tunnel_is_up(struct wg_tunnel *t);
/* Seconds since the last completed handshake, or -1 when there was none. */
long wg_tunnel_handshake_age(struct wg_tunnel *t, uint8_t peer_index);

/* An IPv4 packet from the stack, to encrypt and send. */
int wg_tunnel_output(struct wg_tunnel *t, const uint8_t *packet, size_t len);
/* A UDP datagram received on the tunnel's socket. data is modified in place. */
void wg_tunnel_udp_input(struct wg_tunnel *t, uint8_t *data, size_t len, uint32_t src_ip, uint16_t src_port);
/* Call every WG_TUNNEL_TICK_MSECS. */
void wg_tunnel_tick(struct wg_tunnel *t);

#endif
