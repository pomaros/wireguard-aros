/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * The unit task of wireguard.device. It owns the UDP socket and the tunnel
 * engine: it encrypts what the stack writes, decrypts what arrives and hands
 * it to the stack's read requests, and runs the WireGuard timers.
 *
 * bsdsocket.library is opened here and nowhere else, because a socket base
 * belongs to the task that opened it. It is opened late and retried: the
 * stack opens this device before its own library exists. When the stack
 * shuts down it breaks this task with CTRL-C and waits for the base to be
 * closed, so the task lets go of the socket and keeps running without one.
 */
#include <aros/debug.h>
#include <devices/timer.h>
#include <dos/dos.h>
#include <exec/errors.h>
#include <exec/memory.h>
#include <resources/entropy.h>
#include <proto/entropy.h>
#include <proto/exec.h>
#include <proto/timer.h>

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <proto/bsdsocket.h>

#include "wg_device.h"
#include "wg_tunnel.h"

extern struct ExecBase *SysBase;
extern struct Device *TimerBase;

struct Library *SocketBase;
APTR EntropyBase;

#define IP_TYPE_PPP 0x0021
#define IP_TYPE_ETHER 0x0800
#define TICK_MICROS (WG_TUNNEL_TICK_MSECS * 1000)

struct wg_run {
    struct WGBase *base;
    struct WGUnit *unit;
    struct wg_tunnel tunnel;
    BOOL tunnel_ready;
    ULONG config_serial;
    struct WGDeviceConfig config;
    LONG sock;
    UBYTE socket_state;
    LONG socket_errno;
    BOOL socket_held;           /* released for a stack shutdown; a new configuration lifts it */
    UQUAD rx_no_reader;
    UQUAD udp_send_errors;
    UBYTE packet[WG_TUNNEL_MAX_PACKET];
    UBYTE datagram[WG_TUNNEL_MAX_PACKET + WG_TUNNEL_OVERHEAD + 64];
};

/* ---- what the WireGuard core asks of its platform ---- */

uint32_t wireguard_sys_now(void) {
    struct EClockVal ev;
    ULONG freq = ReadEClock(&ev);
    UQUAD ticks = ((UQUAD)ev.ev_hi << 32) | ev.ev_lo;

    /* Starts above zero: the core reads a zero timestamp as "never". */
    return (uint32_t)(ticks / freq * 1000 + (ticks % freq) * 1000 / freq) + 100000u;
}

void wireguard_random_bytes(void *bytes, size_t size) {
    UBYTE *p = bytes;

    /* The device refuses a configuration when entropy.resource is missing, so EntropyBase is set here. */
    while (size > 0) {
        ULONG n = size > 256 ? 256 : (ULONG)size;
        GetEntropy(p, n);
        p += n;
        size -= n;
    }
}

void wireguard_tai64n_now(uint8_t *output) {
    struct timeval tv;
    UQUAD seconds;
    ULONG nanos;

    GetSysTime(&tv);
    /* The Amiga epoch is 1978-01-01, 252460800 seconds after the Unix one. */
    seconds = 0x400000000000000aULL + 252460800ULL + (UQUAD)tv.tv_secs;
    nanos = (ULONG)tv.tv_micro * 1000;
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

/* ---- the socket ---- */

static BOOL stack_is_up(void) {
    struct Node *lib;

    /* OpenLibrary would go to disk for a missing library, which a plain task must not do. */
    Forbid();
    lib = FindName(&SysBase->LibList, "bsdsocket.library");
    Permit();
    return lib != NULL;
}

static void socket_close(struct wg_run *run) {
    if (SocketBase) {
        if (run->sock >= 0) {
            CloseSocket(run->sock);
        }
        CloseLibrary(SocketBase);
        SocketBase = NULL;
    }
    run->sock = -1;
    if (run->socket_state == WG_SOCKET_OPEN) {
        run->socket_state = WG_SOCKET_NONE;
    }
}

static void socket_open(struct wg_run *run) {
    struct sockaddr_in local;
    LONG on = 1;

    if (run->sock >= 0 || run->socket_held || !run->tunnel_ready) {
        return;
    }
    if (!SocketBase) {
        if (!stack_is_up() || !(SocketBase = OpenLibrary("bsdsocket.library", 4))) {
            run->socket_state = WG_SOCKET_NONE;
            return;
        }
    }
    run->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (run->sock < 0) {
        run->socket_state = WG_SOCKET_FAILED;
        run->socket_errno = Errno();
        return;
    }
    for (ULONG i = 0; i < sizeof(local); i++) {
        ((UBYTE *)&local)[i] = 0;
    }
    local.sin_len = sizeof(local);
    local.sin_family = AF_INET;
    local.sin_port = htons(run->config.listen_port);
    if (bind(run->sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        run->socket_state = WG_SOCKET_FAILED;
        run->socket_errno = Errno();
        CloseSocket(run->sock);
        run->sock = -1;
        return;
    }
    IoctlSocket(run->sock, FIONBIO, (char *)&on);
    run->socket_state = WG_SOCKET_OPEN;
    run->socket_errno = 0;
    D(bug("[wireguard] UDP socket open\n"));
}

static int udp_send(void *ctx, const uint8_t *data, size_t len, uint32_t ip, uint16_t port) {
    struct wg_run *run = ctx;
    struct sockaddr_in to;

    if (run->sock < 0) {
        return -1;
    }
    for (ULONG i = 0; i < sizeof(to); i++) {
        ((UBYTE *)&to)[i] = 0;
    }
    to.sin_len = sizeof(to);
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ip;
    to.sin_port = htons(port);
    if (sendto(run->sock, (APTR)data, (LONG)len, 0, (struct sockaddr *)&to, sizeof(to)) != (LONG)len) {
        run->udp_send_errors++;
        return -1;
    }
    return 0;
}

/* ---- towards the stack ---- */

static void ip_input(void *ctx, const uint8_t *packet, size_t len) {
    struct wg_run *run = ctx;
    struct WGUnit *unit = run->unit;
    struct WGOpener *opener;
    BOOL delivered = FALSE;

    Disable();
    for (opener = (struct WGOpener *)unit->openers.mlh_Head; opener->node.mln_Succ;
         opener = (struct WGOpener *)opener->node.mln_Succ) {
        struct IOSana2Req *req = NULL;
        struct Node *node;

        for (node = opener->read_pending.mp_MsgList.lh_Head; node->ln_Succ; node = node->ln_Succ) {
            ULONG type = ((struct IOSana2Req *)node)->ios2_PacketType;
            if (type == IP_TYPE_PPP || type == IP_TYPE_ETHER) {
                req = (struct IOSana2Req *)node;
                Remove(node);
                break;
            }
        }
        if (!req) {
            continue;
        }
        Enable();
        if (AROS_UFC3(BOOL, opener->rx, AROS_UFCA(APTR, req->ios2_Data, A0), AROS_UFCA(APTR, (APTR)packet, A1),
                      AROS_UFCA(ULONG, (ULONG)len, D0))) {
            req->ios2_DataLength = (ULONG)len;
            req->ios2_Req.io_Error = 0;
            req->ios2_Req.io_Flags &= ~(SANA2IOF_BCAST | SANA2IOF_MCAST);
            unit->stats.PacketsReceived++;
            delivered = TRUE;
        } else {
            req->ios2_Req.io_Error = S2ERR_NO_RESOURCES;
            req->ios2_WireError = S2WERR_BUFF_ERROR;
        }
        ReplyMsg((struct Message *)req);
        /* One protocol stack takes the packet. */
        Disable();
        break;
    }
    Enable();
    if (!delivered) {
        run->rx_no_reader++;
        unit->stats.UnknownTypesReceived++;
    }
}

static void handle_writes(struct wg_run *run) {
    struct WGUnit *unit = run->unit;
    struct IOSana2Req *req;

    while ((req = (struct IOSana2Req *)GetMsg(unit->write_port))) {
        struct WGOpener *opener = req->ios2_BufferManagement;
        ULONG len = req->ios2_DataLength;

        req->ios2_Req.io_Error = 0;
        if (len > sizeof(run->packet) ||
            !AROS_UFC3(BOOL, opener->tx, AROS_UFCA(APTR, run->packet, A0), AROS_UFCA(APTR, req->ios2_Data, A1),
                       AROS_UFCA(ULONG, len, D0))) {
            req->ios2_Req.io_Error = S2ERR_NO_RESOURCES;
            req->ios2_WireError = S2WERR_BUFF_ERROR;
        } else if (run->tunnel_ready) {
            /* Like a wire with no carrier, a tunnel without a session loses the packet without an error. */
            wg_tunnel_output(&run->tunnel, run->packet, len);
            unit->stats.PacketsSent++;
        }
        ReplyMsg((struct Message *)req);
    }
}

static void handle_socket(struct wg_run *run) {
    for (int burst = 0; burst < 64 && run->sock >= 0; burst++) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        LONG n = recvfrom(run->sock, run->datagram, sizeof(run->datagram), 0, (struct sockaddr *)&from, &from_len);

        if (n <= 0) {
            break;
        }
        if (run->tunnel_ready) {
            wg_tunnel_udp_input(&run->tunnel, run->datagram, (size_t)n, from.sin_addr.s_addr, ntohs(from.sin_port));
        }
    }
}

/* ---- configuration and status ---- */

static void tunnel_stop(struct wg_run *run) {
    if (run->tunnel_ready) {
        wg_tunnel_shutdown(&run->tunnel);
        run->tunnel_ready = FALSE;
    }
    for (ULONG i = 0; i < sizeof(run->config); i++) {
        ((volatile UBYTE *)&run->config)[i] = 0;
    }
}

static void apply_config(struct wg_run *run) {
    static const struct wg_tunnel_ops ops = {udp_send, ip_input};
    struct WGBase *base = run->base;
    BOOL valid;
    uint8_t index;

    ObtainSemaphore(&base->lock);
    if (base->config_serial == run->config_serial) {
        ReleaseSemaphore(&base->lock);
        return;
    }
    tunnel_stop(run);
    run->config_serial = base->config_serial;
    valid = base->config_valid;
    if (valid) {
        CopyMem(&base->config, &run->config, sizeof(run->config));
    }
    ReleaseSemaphore(&base->lock);

    /* A new configuration means a program is talking to a running stack again. */
    run->socket_held = FALSE;
    socket_close(run);
    if (!valid) {
        D(bug("[wireguard] configuration cleared\n"));
        return;
    }
    if (!EntropyBase) {
        EntropyBase = OpenResource("entropy.resource");
    }
    if (!EntropyBase) {
        bug("[wireguard] no entropy.resource: refusing to make keys\n");
        tunnel_stop(run);
        return;
    }
    if (wg_tunnel_init(&run->tunnel, run->config.private_key, &ops, run) != WG_OK ||
        wg_tunnel_add_peer(&run->tunnel, run->config.public_key,
                           run->config.has_preshared_key ? run->config.preshared_key : NULL, run->config.endpoint_ip,
                           run->config.endpoint_port, run->config.keepalive, &index) != WG_OK) {
        bug("[wireguard] the configuration was refused\n");
        tunnel_stop(run);
        return;
    }
    for (int i = 0; i < run->config.allowed_count && i < WG_DEVICE_MAX_ALLOWED; i++) {
        wg_tunnel_allow(&run->tunnel, index, run->config.allowed[i].ip, run->config.allowed[i].mask);
    }
    wg_tunnel_connect(&run->tunnel, index);
    run->tunnel_ready = TRUE;
    D(bug("[wireguard] configuration applied, connecting\n"));
}

static void publish_status(struct wg_run *run) {
    struct WGBase *base = run->base;
    struct WGDeviceStatus *s = &base->status;
    struct wg_tunnel_stats *t = &run->tunnel.stats;

    ObtainSemaphore(&base->lock);
    s->configured = run->tunnel_ready;
    s->socket_state = run->socket_held ? WG_SOCKET_HELD : run->socket_state;
    s->socket_errno = run->socket_errno;
    s->rx_no_reader = run->rx_no_reader;
    s->udp_send_errors = run->udp_send_errors;
    if (run->tunnel_ready) {
        s->up = wg_tunnel_is_up(&run->tunnel);
        s->handshake_age = (LONG)wg_tunnel_handshake_age(&run->tunnel, 0);
        s->handshakes_sent = t->handshakes_sent;
        s->handshakes_completed = t->handshakes_completed;
        s->tx_packets = t->tx_packets; s->tx_bytes = t->tx_bytes;
        s->rx_packets = t->rx_packets; s->rx_bytes = t->rx_bytes;
        s->rx_bad_auth = t->rx_bad_auth; s->rx_replayed = t->rx_replayed;
        s->rx_bad_source = t->rx_bad_source; s->rx_malformed = t->rx_malformed;
        s->tx_no_session = t->tx_no_session;
    } else {
        s->up = FALSE;
        s->handshake_age = -1;
    }
    ReleaseSemaphore(&base->lock);
}

/* ---- the task ---- */

static void arm_timer(struct timerequest *tr) {
    tr->tr_node.io_Command = TR_ADDREQUEST;
    tr->tr_time.tv_secs = 0;
    tr->tr_time.tv_micro = TICK_MICROS;
    SendIO((struct IORequest *)tr);
}

void wg_unit_task(struct WGBase *base, struct WGUnit *unit) {
    struct wg_run *run = AllocMem(sizeof(*run), MEMF_PUBLIC | MEMF_CLEAR);
    struct MsgPort *timer_port = CreateMsgPort();
    struct MsgPort *write_port = CreateMsgPort();
    struct timerequest tr;
    LONG stop_signal = AllocSignal(-1), config_signal = AllocSignal(-1);
    ULONG wait_mask, got;
    BOOL running;

    if (!run || !timer_port || !write_port || stop_signal < 0 || config_signal < 0) {
        if (run) {
            FreeMem(run, sizeof(*run));
        }
        if (timer_port) {
            DeleteMsgPort(timer_port);
        }
        if (write_port) {
            DeleteMsgPort(write_port);
        }
        /* The opener sees write_port NULL, frees the unit and fails the open. */
        Forbid();
        base->tasks_alive--;
        PutMsg(unit->sync_port, &unit->start_msg);
        return;
    }

    run->base = base;
    run->unit = unit;
    run->sock = -1;
    run->config_serial = 0;
    unit->stop_signal = stop_signal;
    unit->config_signal = config_signal;
    unit->write_port = write_port;

    tr.tr_node.io_Message.mn_Node.ln_Type = NT_REPLYMSG;
    tr.tr_node.io_Message.mn_ReplyPort = timer_port;
    tr.tr_node.io_Message.mn_Length = sizeof(tr);
    tr.tr_node.io_Device = base->timer_io.tr_node.io_Device;
    tr.tr_node.io_Unit = base->timer_io.tr_node.io_Unit;

    PutMsg(unit->sync_port, &unit->start_msg);

    apply_config(run); /* a configuration may be waiting from before this open */
    arm_timer(&tr);

    wait_mask = (1UL << stop_signal) | (1UL << config_signal) | (1UL << timer_port->mp_SigBit) |
                (1UL << write_port->mp_SigBit) | SIGBREAKF_CTRL_C;

    for (running = TRUE; running;) {
        if (run->sock >= 0) {
            fd_set readable;
            got = wait_mask;
            FD_ZERO(&readable);
            FD_SET(run->sock, &readable);
            if (WaitSelect(run->sock + 1, &readable, NULL, NULL, NULL, &got) > 0) {
                handle_socket(run);
            }
        } else {
            got = Wait(wait_mask);
        }

        if (got & (1UL << stop_signal)) {
            running = FALSE;
        }
        if (got & SIGBREAKF_CTRL_C) {
            /* The stack is shutting down and waits for every socket base to close. */
            socket_close(run);
            run->socket_held = TRUE;
            D(bug("[wireguard] stack shutting down, socket released\n"));
        }
        if (got & (1UL << config_signal)) {
            apply_config(run);
        }
        if (got & (1UL << write_port->mp_SigBit)) {
            handle_writes(run);
        }
        if (got & (1UL << timer_port->mp_SigBit)) {
            if (GetMsg(timer_port)) {
                socket_open(run);
                if (run->tunnel_ready && run->sock >= 0) {
                    wg_tunnel_tick(&run->tunnel);
                }
                publish_status(run);
                arm_timer(&tr);
            }
        }
    }

    AbortIO((struct IORequest *)&tr);
    WaitIO((struct IORequest *)&tr);
    socket_close(run);
    tunnel_stop(run);
    publish_status(run);

    /* Nobody else knows this unit any more: the last opener has closed. */
    {
        struct IOSana2Req *req;
        while ((req = (struct IOSana2Req *)GetMsg(write_port))) {
            req->ios2_Req.io_Error = IOERR_ABORTED;
            ReplyMsg((struct Message *)req);
        }
    }
    DeleteMsgPort(write_port);
    DeleteMsgPort(timer_port);
    DeleteMsgPort(unit->sync_port);
    FreeSignal(stop_signal);
    FreeSignal(config_signal);
    FreeMem(run, sizeof(*run));
    FreeMem(unit, sizeof(*unit));
    D(bug("[wireguard] unit task ended\n"));
    Forbid();
    base->tasks_alive--;
}
