/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026 John Knipper
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the BSD 3-Clause licence
 * in third_party/wireguard-lwip/LICENSE.
 *
 * The peer state machine, the timer rules and the receive path follow
 * wireguardif.c of wireguard-lwip. The lwIP netif, pbuf and UDP calls are
 * replaced by two caller-supplied functions and flat buffers.
 */
#include "wg_tunnel.h"

#include <string.h>

#include "crypto.h"

/* Addresses are kept in network byte order; a prefix test only needs equality under the mask. */
static bool net_match(uint32_t a, uint32_t ip, uint32_t mask) {
    return ((a ^ ip) & mask) == 0;
}

static struct wireguard_peer *peer_by_allowed_ip(struct wireguard_device *device, uint32_t ip) {
    for (int x = 0; x < WIREGUARD_MAX_PEERS; x++) {
        struct wireguard_peer *peer = &device->peers[x];
        if (!peer->valid) {
            continue;
        }
        for (int y = 0; y < WIREGUARD_MAX_SRC_IPS; y++) {
            struct wireguard_allowed_ip *a = &peer->allowed_source_ips[y];
            if (a->valid && net_match(ip, a->ip.addr, a->mask.addr)) {
                return peer;
            }
        }
    }
    return NULL;
}

static bool source_allowed(struct wireguard_peer *peer, uint32_t ip) {
    for (int y = 0; y < WIREGUARD_MAX_SRC_IPS; y++) {
        struct wireguard_allowed_ip *a = &peer->allowed_source_ips[y];
        if (a->valid && net_match(ip, a->ip.addr, a->mask.addr)) {
            return true;
        }
    }
    return false;
}

static int send_to_peer(struct wg_tunnel *t, struct wireguard_peer *peer, const uint8_t *data, size_t len) {
    /* The last authenticated address, which roams, and never the configured one. */
    return t->ops.udp_send(t->ctx, data, len, peer->ip.addr, peer->port);
}

/* packet == NULL sends a keepalive. */
static int output_to_peer(struct wg_tunnel *t, struct wireguard_peer *peer, const uint8_t *packet, size_t len) {
    struct wireguard_keypair *keypair = &peer->curr_keypair;

    /* A responder may not use a session before the initiator has proved it holds the keys. */
    if (keypair->valid && !keypair->initiator && keypair->last_rx == 0) {
        keypair = &peer->prev_keypair;
    }
    if (!(keypair->valid && (keypair->initiator || keypair->last_rx != 0))) {
        t->stats.tx_no_session++;
        return WG_ERR_NO_SESSION;
    }
    if (wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME) || keypair->sending_counter >= REJECT_AFTER_MESSAGES) {
        keypair_destroy(keypair);
        t->stats.tx_no_session++;
        return WG_ERR_NO_SESSION;
    }
    if (len > WG_TUNNEL_MAX_PACKET) {
        return WG_ERR_TOO_BIG;
    }

    size_t padded = (len + 15) & ~(size_t)15;
    size_t total = 16 + padded + WIREGUARD_AUTHTAG_LEN;
    struct message_transport_data *hdr = (struct message_transport_data *)t->scratch;

    memset(t->scratch, 0, total);
    hdr->type = MESSAGE_TRANSPORT_DATA;
    hdr->receiver = keypair->remote_index;
    U64TO8_LITTLE(hdr->counter, keypair->sending_counter);
    if (len > 0) {
        memcpy(hdr->enc_packet, packet, len);
    }
    wireguard_encrypt_packet(hdr->enc_packet, hdr->enc_packet, padded, keypair);

    int sent = send_to_peer(t, peer, t->scratch, total);
    if (sent == 0) {
        uint32_t now = wireguard_sys_now();
        peer->last_tx = now;
        keypair->last_tx = now;
        if (len > 0) {
            t->stats.tx_packets++;
            t->stats.tx_bytes += len;
        }
    }

    if (keypair->sending_counter >= REKEY_AFTER_MESSAGES) {
        peer->send_handshake = true;
    } else if (keypair->initiator && wireguard_expired(keypair->keypair_millis, REKEY_AFTER_TIME)) {
        peer->send_handshake = true;
    }
    return sent == 0 ? WG_OK : WG_ERR_SEND;
}

static size_t source_addr_port(uint32_t ip, uint16_t port, uint8_t *buf) {
    memcpy(buf, &ip, 4);
    buf[4] = (uint8_t)(port >> 8);
    buf[5] = (uint8_t)port;
    return 6;
}

static void send_cookie(struct wg_tunnel *t, const uint8_t *mac1, uint32_t index, uint32_t ip, uint16_t port) {
    struct message_cookie_reply packet;
    uint8_t source[6];
    size_t source_len = source_addr_port(ip, port, source);

    wireguard_create_cookie_reply(&t->device, &packet, mac1, index, source, source_len);
    t->ops.udp_send(t->ctx, (const uint8_t *)&packet, sizeof(packet), ip, port);
}

/* Checks mac1, and mac2 under load. mac1 and mac2 are the last two 16-byte fields of every handshake message. */
static bool check_macs(struct wg_tunnel *t, uint8_t *data, size_t msg_len, uint32_t sender, uint32_t ip, uint16_t port) {
    uint8_t *mac1 = data + msg_len - 2 * WIREGUARD_COOKIE_LEN;
    uint8_t *mac2 = data + msg_len - WIREGUARD_COOKIE_LEN;

    if (!wireguard_check_mac1(&t->device, data, msg_len - 2 * WIREGUARD_COOKIE_LEN, mac1)) {
        return false;
    }
    if (!wireguard_is_under_load()) {
        return true;
    }
    uint8_t source[6];
    size_t source_len = source_addr_port(ip, port, source);
    if (wireguard_check_mac2(&t->device, data, msg_len - WIREGUARD_COOKIE_LEN, source, source_len, mac2)) {
        return true;
    }
    send_cookie(t, mac1, sender, ip, port);
    return false;
}

static void process_data(struct wg_tunnel *t, struct wireguard_peer *peer, struct message_transport_data *hdr,
                         size_t enc_len, uint32_t src_ip, uint16_t src_port) {
    struct wireguard_keypair *keypair = get_peer_keypair_for_idx(peer, hdr->receiver);

    if (!keypair) {
        return;
    }
    if (!keypair->receiving_valid || wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME)) {
        keypair_destroy(keypair);
        return;
    }
    if (enc_len < WIREGUARD_AUTHTAG_LEN || enc_len - WIREGUARD_AUTHTAG_LEN > sizeof(t->scratch)) {
        t->stats.rx_malformed++;
        return;
    }

    uint64_t nonce = U8TO64_LITTLE(hdr->counter);
    /* The counter is unauthenticated here, so a value past the limit drops the packet and leaves the keys alone. */
    if (nonce >= REJECT_AFTER_MESSAGES) {
        return;
    }

    size_t plain_len = enc_len - WIREGUARD_AUTHTAG_LEN;
    uint8_t *plain = t->scratch;

    if (!wireguard_decrypt_packet(plain, hdr->enc_packet, enc_len, nonce, keypair)) {
        t->stats.rx_bad_auth++;
        return;
    }
    /* The replay window is consulted only after the tag verified, and before any peer state changes. */
    if (!wireguard_check_replay(keypair, nonce)) {
        t->stats.rx_replayed++;
        return;
    }

    peer->ip.addr = src_ip;
    peer->port = src_port;

    uint32_t now = wireguard_sys_now();
    keypair->last_rx = now;
    peer->last_rx = now;

    if (keypair->initiator &&
        wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME - peer->keepalive_interval - REKEY_TIMEOUT)) {
        peer->send_handshake = true;
    }

    /* May promote the next keypair to current; keypair must not be used after this. */
    keypair_update(peer, keypair);

    if (plain_len == 0) {
        return; /* keepalive */
    }
    if (plain_len < 20 || (plain[0] >> 4) != 4) {
        t->stats.rx_malformed++;
        return;
    }
    size_t ip_len = ((size_t)plain[2] << 8) | plain[3];
    size_t ip_hlen = (size_t)(plain[0] & 0x0f) * 4;
    if (ip_hlen < 20 || ip_len < ip_hlen || ip_len > plain_len) {
        t->stats.rx_malformed++;
        return;
    }
    uint32_t inner_src;
    memcpy(&inner_src, plain + 12, 4);
    if (!source_allowed(peer, inner_src)) {
        t->stats.rx_bad_source++;
        return;
    }
    t->stats.rx_packets++;
    t->stats.rx_bytes += ip_len;
    t->ops.ip_input(t->ctx, plain, ip_len);
}

static void start_handshake(struct wg_tunnel *t, struct wireguard_peer *peer) {
    struct message_handshake_initiation msg;

    if (!wireguard_create_handshake_initiation(&t->device, peer, &msg)) {
        return;
    }
    send_to_peer(t, peer, (const uint8_t *)&msg, sizeof(msg));
    peer->send_handshake = false;
    peer->last_initiation_tx = wireguard_sys_now();
    memcpy(peer->handshake_mac1, msg.mac1, WIREGUARD_COOKIE_LEN);
    peer->handshake_mac1_valid = true;
    t->stats.handshakes_sent++;
}

void wg_tunnel_udp_input(struct wg_tunnel *t, uint8_t *data, size_t len, uint32_t src_ip, uint16_t src_port) {
    struct wireguard_peer *peer;

    switch (wireguard_get_message_type(data, len)) {
    case MESSAGE_HANDSHAKE_INITIATION: {
        struct message_handshake_initiation *msg = (struct message_handshake_initiation *)data;
        if (!check_macs(t, data, sizeof(*msg), msg->sender, src_ip, src_port)) {
            break;
        }
        peer = wireguard_process_initiation_message(&t->device, msg);
        if (peer) {
            struct message_handshake_response response;
            peer->ip.addr = src_ip;
            peer->port = src_port;
            if (wireguard_create_handshake_response(&t->device, peer, &response)) {
                wireguard_start_session(peer, false);
                send_to_peer(t, peer, (const uint8_t *)&response, sizeof(response));
                t->stats.handshakes_completed++;
            }
        }
        break;
    }
    case MESSAGE_HANDSHAKE_RESPONSE: {
        struct message_handshake_response *msg = (struct message_handshake_response *)data;
        if (!check_macs(t, data, sizeof(*msg), msg->sender, src_ip, src_port)) {
            break;
        }
        peer = peer_lookup_by_handshake(&t->device, msg->receiver);
        if (peer && wireguard_process_handshake_response(&t->device, peer, msg)) {
            peer->ip.addr = src_ip;
            peer->port = src_port;
            wireguard_start_session(peer, true);
            t->stats.handshakes_completed++;
            /* The first transport message confirms the session to the responder. */
            output_to_peer(t, peer, NULL, 0);
        }
        break;
    }
    case MESSAGE_COOKIE_REPLY: {
        struct message_cookie_reply *msg = (struct message_cookie_reply *)data;
        peer = peer_lookup_by_handshake(&t->device, msg->receiver);
        if (peer) {
            wireguard_process_cookie_message(&t->device, peer, msg);
        }
        break;
    }
    case MESSAGE_TRANSPORT_DATA: {
        struct message_transport_data *msg = (struct message_transport_data *)data;
        peer = peer_lookup_by_receiver(&t->device, msg->receiver);
        if (peer) {
            process_data(t, peer, msg, len - 16, src_ip, src_port);
        }
        break;
    }
    default:
        break;
    }
}

int wg_tunnel_output(struct wg_tunnel *t, const uint8_t *packet, size_t len) {
    if (len < 20 || (packet[0] >> 4) != 4) {
        return WG_ERR_ARG;
    }
    uint32_t dst;
    memcpy(&dst, packet + 16, 4);
    struct wireguard_peer *peer = peer_by_allowed_ip(&t->device, dst);
    if (!peer) {
        return WG_ERR_NO_ROUTE;
    }
    int result = output_to_peer(t, peer, packet, len);
    if (result == WG_ERR_NO_SESSION && peer->active) {
        peer->send_handshake = true;
    }
    return result;
}

static bool can_send_initiation(struct wireguard_peer *peer) {
    return peer->last_initiation_tx == 0 || wireguard_expired(peer->last_initiation_tx, REKEY_TIMEOUT);
}

static bool should_send_initiation(struct wireguard_peer *peer) {
    if (!can_send_initiation(peer)) {
        return false;
    }
    if (peer->send_handshake) {
        return true;
    }
    if (peer->curr_keypair.valid && !peer->curr_keypair.initiator &&
        wireguard_expired(peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME - peer->keepalive_interval)) {
        return true;
    }
    return !peer->curr_keypair.valid && peer->active;
}

static bool should_send_keepalive(struct wireguard_peer *peer) {
    return peer->keepalive_interval > 0 && (peer->curr_keypair.valid || peer->prev_keypair.valid) &&
           wireguard_expired(peer->last_tx, peer->keepalive_interval);
}

static bool should_destroy_keypair(struct wireguard_keypair *keypair) {
    return keypair->valid && (wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME) ||
                              keypair->sending_counter >= REJECT_AFTER_MESSAGES);
}

void wg_tunnel_tick(struct wg_tunnel *t) {
    for (int x = 0; x < WIREGUARD_MAX_PEERS; x++) {
        struct wireguard_peer *peer = &t->device.peers[x];
        if (!peer->valid) {
            continue;
        }
        /* No new session for three reject periods: wipe every key and go back to the configured endpoint. */
        if (peer->last_session_millis != 0 && wireguard_expired(peer->last_session_millis, REJECT_AFTER_TIME * 3)) {
            keypair_destroy(&peer->next_keypair);
            keypair_destroy(&peer->curr_keypair);
            keypair_destroy(&peer->prev_keypair);
            crypto_zero(&peer->handshake, sizeof(peer->handshake));
            peer->handshake.valid = false;
            peer->last_session_millis = 0;
            if (peer->connect_ip.addr != 0 && peer->connect_port != 0) {
                peer->ip = peer->connect_ip;
                peer->port = peer->connect_port;
            }
        }
        if (should_destroy_keypair(&peer->curr_keypair)) {
            keypair_destroy(&peer->curr_keypair);
        }
        if (should_destroy_keypair(&peer->prev_keypair)) {
            keypair_destroy(&peer->prev_keypair);
        }
        if (should_destroy_keypair(&peer->next_keypair)) {
            keypair_destroy(&peer->next_keypair);
        }
        if (should_send_keepalive(peer)) {
            output_to_peer(t, peer, NULL, 0);
        }
        if (should_send_initiation(peer)) {
            start_handshake(t, peer);
        }
    }
}

bool wg_tunnel_is_up(struct wg_tunnel *t) {
    for (int x = 0; x < WIREGUARD_MAX_PEERS; x++) {
        struct wireguard_peer *peer = &t->device.peers[x];
        if (peer->valid && (peer->curr_keypair.valid || peer->prev_keypair.valid)) {
            return true;
        }
    }
    return false;
}

long wg_tunnel_handshake_age(struct wg_tunnel *t, uint8_t peer_index) {
    struct wireguard_peer *peer = peer_lookup_by_peer_index(&t->device, peer_index);
    if (!peer || peer->last_session_millis == 0) {
        return -1;
    }
    return (long)((wireguard_sys_now() - peer->last_session_millis) / 1000);
}

int wg_tunnel_init(struct wg_tunnel *t, const uint8_t *private_key, const struct wg_tunnel_ops *ops, void *ctx) {
    static bool core_ready;

    if (!t || !private_key || !ops || !ops->udp_send || !ops->ip_input) {
        return WG_ERR_ARG;
    }
    if (!core_ready) {
        wireguard_init();
        core_ready = true;
    }
    memset(t, 0, sizeof(*t));
    t->ops = *ops;
    t->ctx = ctx;
    if (!wireguard_device_init(&t->device, private_key)) {
        return WG_ERR_ARG;
    }
    return WG_OK;
}

void wg_tunnel_shutdown(struct wg_tunnel *t) {
    crypto_zero(t, sizeof(*t));
}

int wg_tunnel_add_peer(struct wg_tunnel *t, const uint8_t *public_key, const uint8_t *preshared_key,
                       uint32_t endpoint_ip, uint16_t endpoint_port, uint16_t keepalive, uint8_t *peer_index) {
    struct wireguard_peer *peer = peer_alloc(&t->device);

    if (!peer || !wireguard_peer_init(&t->device, peer, public_key, preshared_key)) {
        return WG_ERR_ARG;
    }
    peer->connect_ip.addr = endpoint_ip;
    peer->connect_port = endpoint_port;
    peer->ip = peer->connect_ip;
    peer->port = peer->connect_port;
    peer->keepalive_interval = keepalive;
    if (peer_index) {
        *peer_index = wireguard_peer_index(&t->device, peer);
    }
    return WG_OK;
}

int wg_tunnel_allow(struct wg_tunnel *t, uint8_t peer_index, uint32_t ip, uint32_t mask) {
    struct wireguard_peer *peer = peer_lookup_by_peer_index(&t->device, peer_index);

    if (!peer) {
        return WG_ERR_ARG;
    }
    for (int x = 0; x < WIREGUARD_MAX_SRC_IPS; x++) {
        struct wireguard_allowed_ip *a = &peer->allowed_source_ips[x];
        if (!a->valid) {
            a->valid = true;
            a->ip.addr = ip & mask;
            a->mask.addr = mask;
            return WG_OK;
        }
    }
    return WG_ERR_ARG;
}

int wg_tunnel_connect(struct wg_tunnel *t, uint8_t peer_index) {
    struct wireguard_peer *peer = peer_lookup_by_peer_index(&t->device, peer_index);

    if (!peer || peer->connect_ip.addr == 0 || peer->connect_port == 0) {
        return WG_ERR_ARG;
    }
    peer->active = true;
    peer->ip = peer->connect_ip;
    peer->port = peer->connect_port;
    return WG_OK;
}

int wg_tunnel_disconnect(struct wg_tunnel *t, uint8_t peer_index) {
    struct wireguard_peer *peer = peer_lookup_by_peer_index(&t->device, peer_index);

    if (!peer) {
        return WG_ERR_ARG;
    }
    peer->active = false;
    keypair_destroy(&peer->next_keypair);
    keypair_destroy(&peer->curr_keypair);
    keypair_destroy(&peer->prev_keypair);
    return WG_OK;
}
