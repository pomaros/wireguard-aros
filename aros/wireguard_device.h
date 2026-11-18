/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * The private interface of wireguard.device: three commands a program sends
 * with an IOSana2Req after opening the device itself. ios2_StatData points to
 * the structure and ios2_DataLength holds its size.
 */
#ifndef WIREGUARD_DEVICE_H
#define WIREGUARD_DEVICE_H

#include <exec/types.h>

#define WG_DEVICE_NAME "DEVS:Networks/wireguard.device"

#define WGCMD_SETCONFIG 0x5741 /* struct WGDeviceConfig in; starts the tunnel */
#define WGCMD_GETSTATUS 0x5742 /* struct WGDeviceStatus out */
#define WGCMD_CLEAR     0x5743 /* no data; stops the tunnel and wipes its keys */

#define WG_DEVICE_MAX_ALLOWED 4
#define WG_DEVICE_MTU 1420

/* Addresses are in network byte order, ports in host order. */
struct WGDeviceConfig {
    UBYTE private_key[32];
    UBYTE public_key[32];
    UBYTE preshared_key[32];
    UBYTE has_preshared_key;
    UBYTE allowed_count;
    UWORD listen_port;
    ULONG endpoint_ip;
    UWORD endpoint_port;
    UWORD keepalive;
    struct {
        ULONG ip, mask;
    } allowed[WG_DEVICE_MAX_ALLOWED];
};

/* socket_state */
#define WG_SOCKET_NONE    0 /* no TCP/IP stack to open a socket on */
#define WG_SOCKET_OPEN    1
#define WG_SOCKET_FAILED  2 /* socket() or bind() failed, see socket_errno */
#define WG_SOCKET_HELD    3 /* released because the stack is shutting down */

struct WGDeviceStatus {
    UBYTE configured;
    UBYTE up;                 /* a session exists */
    UBYTE online;             /* the stack has set the interface online */
    UBYTE socket_state;
    LONG socket_errno;
    LONG handshake_age;       /* seconds since the last handshake, -1 for none */
    ULONG handshakes_sent;
    ULONG handshakes_completed;
    UQUAD tx_packets, tx_bytes;
    UQUAD rx_packets, rx_bytes;
    UQUAD rx_bad_auth, rx_replayed, rx_bad_source, rx_malformed;
    UQUAD tx_no_session;
    UQUAD rx_no_reader;       /* decrypted packets with no read request waiting */
    UQUAD udp_send_errors;
};

#endif
