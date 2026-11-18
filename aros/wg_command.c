/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * WireGuard UP FILE <configuration> [NOROUTE] [NODNS]
 * WireGuard DOWN
 * WireGuard STATUS
 * WireGuard EXITIP
 *
 * UP reads a standard WireGuard configuration file, hands the keys to
 * wireguard.device, makes sure the TCP/IP stack has the interface wg0,
 * gives it the tunnel's address, and routes the AllowedIPs through it. The
 * route to the endpoint itself keeps going through the gateway it used
 * before, so the encrypted packets do not enter the tunnel they carry.
 *
 * EXITIP asks a public service which address the Internet sees, and
 * resolves its name first: one line that shows where DNS and traffic leave.
 */
#include <devices/sana2.h>
#include <dos/dos.h>
#include <dos/rdargs.h>
#include <exec/memory.h>
#include <proto/dos.h>
#include <proto/exec.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netdb.h>
#include <proto/bsdsocket.h>
#include <proto/miami.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef PF_ROUTE
#define PF_ROUTE 17 /* the routing socket family of the BSD stack */
#endif

#include <stdint.h>

#include "wg_config.h"
#include "wireguard_device.h"

#define IFACE "wg0"
#define INTERFACES_FILE "ENV:AROSTCP/db/interfaces"
#define STATE_FILE "ENV:WireGuard.state"
#define CTRL_PORT "AROSTCP.ctrl"
#define NCMD_RELOAD 1

const TEXT version[] = "$VER: WireGuard 0.1 (18.11.2026)";

struct Library *SocketBase;
struct Library *MiamiBase;

/* The stack's control message, as bsdsocket/netcontrol.h declares it. */
struct NetControlMsg {
    struct Message ncm_Msg;
    ULONG ncm_Command;
    LONG ncm_Result;
};

/* What UP did, kept for DOWN. It holds addresses and no key. */
struct wg_state {
    ULONG magic;
    ULONG address, peer, endpoint, gateway;
    ULONG routes;
    struct {
        ULONG ip, mask;
    } route[2 * WG_CONFIG_MAX_ALLOWED];
    UBYTE host_route, dns_set;
};
#define STATE_MAGIC 0x57475331

/*
 * The command links the WireGuard core for its base64 decoder only. The
 * core's handshake code is never reached from here, and its three platform
 * functions exist to satisfy the linker.
 */
uint32_t wireguard_sys_now(void) { return 1; }
void wireguard_random_bytes(void *bytes, size_t size) { memset(bytes, 0, size); }
void wireguard_tai64n_now(uint8_t *output) { memset(output, 0, 12); }

/* ---- the device ---- */

struct dev {
    struct MsgPort *port;
    struct IOSana2Req *req;
    BOOL open;
};

static BOOL dev_open(struct dev *d) {
    static struct TagItem no_tags[] = {{TAG_END, 0}};

    memset(d, 0, sizeof(*d));
    d->port = CreateMsgPort();
    d->req = d->port ? (struct IOSana2Req *)CreateIORequest(d->port, sizeof(struct IOSana2Req)) : NULL;
    if (!d->req) {
        return FALSE;
    }
    d->req->ios2_BufferManagement = no_tags;
    d->open = OpenDevice(WG_DEVICE_NAME, 0, (struct IORequest *)d->req, 0) == 0;
    return d->open;
}

static void dev_close(struct dev *d) {
    if (d->open) {
        CloseDevice((struct IORequest *)d->req);
    }
    if (d->req) {
        DeleteIORequest((struct IORequest *)d->req);
    }
    if (d->port) {
        DeleteMsgPort(d->port);
    }
}

static LONG dev_command(struct dev *d, UWORD command, APTR data, ULONG size) {
    d->req->ios2_Req.io_Command = command;
    d->req->ios2_StatData = data;
    d->req->ios2_DataLength = size;
    return DoIO((struct IORequest *)d->req);
}

/* ---- the stack ---- */

static void in_addr_set(struct sockaddr *sa, ULONG ip) {
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;

    memset(sin, 0, sizeof(*sin));
    sin->sin_len = sizeof(*sin);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;
}

static BOOL iface_exists(LONG s) {
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, IFACE);
    return IoctlSocket(s, SIOCGIFFLAGS, (char *)&ifr) == 0;
}

static BOOL iface_flags(LONG s, BOOL up) {
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, IFACE);
    if (IoctlSocket(s, SIOCGIFFLAGS, (char *)&ifr) != 0) {
        return FALSE;
    }
    if (up) {
        ifr.ifr_flags |= IFF_UP;
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }
    return IoctlSocket(s, SIOCSIFFLAGS, (char *)&ifr) == 0;
}

static BOOL stack_reload(void) {
    struct MsgPort *reply = CreateMsgPort(), *ctrl;
    struct NetControlMsg msg;
    BOOL sent = FALSE;

    if (!reply) {
        return FALSE;
    }
    memset(&msg, 0, sizeof(msg));
    msg.ncm_Msg.mn_ReplyPort = reply;
    msg.ncm_Msg.mn_Length = sizeof(msg);
    msg.ncm_Command = NCMD_RELOAD;
    msg.ncm_Result = -1;
    Forbid();
    ctrl = FindPort(CTRL_PORT);
    if (ctrl) {
        PutMsg(ctrl, &msg.ncm_Msg);
        sent = TRUE;
    }
    Permit();
    if (sent) {
        WaitPort(reply);
        GetMsg(reply);
    }
    DeleteMsgPort(reply);
    return sent && msg.ncm_Result == 0;
}

/* Adds the wg0 line to the stack's interface list unless it is there, and has the stack read the list again. */
static BOOL iface_create(void) {
    static const char line[] = IFACE " DEV=" WG_DEVICE_NAME " UNIT=0 NOTRACKING\n";
    static char text[8192];
    BPTR fh = Open(INTERFACES_FILE, MODE_OLDFILE);
    LONG len = 0;
    BOOL present = FALSE;

    if (fh) {
        len = Read(fh, text, sizeof(text) - 1);
        Close(fh);
        if (len < 0) {
            len = 0;
        }
        text[len] = 0;
        present = strstr(text, "wireguard.device") != NULL;
    }
    if (!present) {
        fh = Open(INTERFACES_FILE, MODE_READWRITE);
        if (!fh) {
            return FALSE;
        }
        Seek(fh, 0, OFFSET_END);
        if (len > 0 && text[len - 1] != '\n') {
            Write(fh, "\n", 1);
        }
        Write(fh, (APTR)line, sizeof(line) - 1);
        Close(fh);
    }
    return stack_reload();
}

static BOOL iface_address(LONG s, ULONG address, ULONG peer, BOOL add) {
    struct ifaliasreq ifra;

    memset(&ifra, 0, sizeof(ifra));
    strcpy(ifra.ifra_name, IFACE);
    in_addr_set(&ifra.ifra_addr, address);
    in_addr_set(&ifra.ifra_broadaddr, peer); /* the destination address of a point-to-point interface */
    in_addr_set(&ifra.ifra_mask, 0xffffffffu);
    return IoctlSocket(s, add ? SIOCAIFADDR : SIOCDIFADDR, (char *)&ifra) == 0;
}

/* ---- routes ---- */

#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

struct route_message {
    struct rt_msghdr hdr;
    char space[256];
};

static char *put_addr(char *cp, ULONG ip) {
    in_addr_set((struct sockaddr *)cp, ip);
    return cp + ROUNDUP(sizeof(struct sockaddr_in));
}

/* gateway is the next hop. Returns 0, or the stack's error number. */
static LONG route_change(int command, ULONG dst, ULONG mask, ULONG gateway, BOOL host) {
    static LONG seq;
    struct route_message m;
    char *cp = m.space;
    LONG s = socket(PF_ROUTE, SOCK_RAW, 0), result = 0;

    if (s < 0) {
        return Errno();
    }
    memset(&m, 0, sizeof(m));
    m.hdr.rtm_type = command;
    m.hdr.rtm_version = RTM_VERSION;
    m.hdr.rtm_seq = ++seq;
    m.hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC | (host ? RTF_HOST : 0);
    m.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | (host ? 0 : RTA_NETMASK);
    cp = put_addr(cp, dst);
    cp = put_addr(cp, gateway);
    if (!host) {
        cp = put_addr(cp, mask);
    }
    m.hdr.rtm_msglen = (u_short)(cp - (char *)&m);
    if (send(s, (char *)&m, m.hdr.rtm_msglen, 0) < 0) {
        result = Errno();
    }
    CloseSocket(s);
    return result;
}

/* The gateway the stack would use to reach ip, or 0 when ip is on a directly attached network. */
static ULONG route_gateway(ULONG ip) {
    static LONG seq = 1000;
    struct route_message m;
    char *cp = m.space;
    LONG s = socket(PF_ROUTE, SOCK_RAW, 0), n;
    ULONG gateway = 0;

    if (s < 0) {
        return 0;
    }
    memset(&m, 0, sizeof(m));
    m.hdr.rtm_type = RTM_GET;
    m.hdr.rtm_version = RTM_VERSION;
    m.hdr.rtm_seq = ++seq;
    m.hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_HOST;
    m.hdr.rtm_addrs = RTA_DST;
    cp = put_addr(cp, ip);
    m.hdr.rtm_msglen = (u_short)(cp - (char *)&m);
    if (send(s, (char *)&m, m.hdr.rtm_msglen, 0) >= 0) {
        do {
            n = recv(s, (char *)&m, sizeof(m), 0);
        } while (n > 0 && m.hdr.rtm_seq != seq);
        if (n > 0 && m.hdr.rtm_errno == 0 && (m.hdr.rtm_flags & RTF_GATEWAY) && (m.hdr.rtm_addrs & RTA_GATEWAY)) {
            struct sockaddr *sa = (struct sockaddr *)m.space;
            if (m.hdr.rtm_addrs & RTA_DST) {
                sa = (struct sockaddr *)((char *)sa + ROUNDUP(sa->sa_len));
            }
            if (sa->sa_family == AF_INET) {
                gateway = ((struct sockaddr_in *)sa)->sin_addr.s_addr;
            }
        }
    }
    CloseSocket(s);
    return gateway;
}

/* ---- small helpers ---- */

static void print_ip(ULONG ip) {
    UBYTE *b = (UBYTE *)&ip;

    printf("%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static ULONG make_ip(UBYTE a, UBYTE b, UBYTE c, UBYTE d) {
    UBYTE bytes[4] = {a, b, c, d};
    ULONG ip;

    memcpy(&ip, bytes, 4);
    return ip;
}

static BOOL state_save(const struct wg_state *st) {
    BPTR fh = Open(STATE_FILE, MODE_NEWFILE);
    BOOL ok;

    if (!fh) {
        return FALSE;
    }
    ok = Write(fh, (APTR)st, sizeof(*st)) == sizeof(*st);
    Close(fh);
    return ok;
}

static BOOL state_load(struct wg_state *st) {
    BPTR fh = Open(STATE_FILE, MODE_OLDFILE);
    BOOL ok;

    if (!fh) {
        return FALSE;
    }
    ok = Read(fh, st, sizeof(*st)) == sizeof(*st) && st->magic == STATE_MAGIC;
    Close(fh);
    return ok;
}

static void dns_set(const struct wg_config *cfg) {
    MiamiBase = OpenLibrary("miami.library", 0);
    if (!MiamiBase) {
        printf("WireGuard: miami.library is missing, the name servers stay as they were\n");
        return;
    }
    ClearDynNameServ();
    for (int i = 0; i < cfg->dns_count; i++) {
        struct sockaddr_in ns;
        in_addr_set((struct sockaddr *)&ns, cfg->dns[i]);
        AddDynNameServ((struct sockaddr *)&ns);
    }
    EndDynNameServ();
    CloseLibrary(MiamiBase);
}

/* ---- the commands ---- */

static int tear_down(struct dev *d, LONG s, const struct wg_state *st) {
    for (ULONG i = 0; i < st->routes; i++) {
        route_change(RTM_DELETE, st->route[i].ip, st->route[i].mask, st->peer, FALSE);
    }
    if (st->host_route) {
        route_change(RTM_DELETE, st->endpoint, 0xffffffffu, st->gateway, TRUE);
    }
    iface_flags(s, FALSE);
    iface_address(s, st->address, st->peer, FALSE);
    dev_command(d, WGCMD_CLEAR, NULL, 0);
    DeleteFile(STATE_FILE);
    return 0;
}

static int command_up(const char *file, BOOL noroute, BOOL nodns) {
    static char text[8192];
    static struct wg_config cfg;
    static struct WGDeviceConfig dc;
    struct wg_state st;
    struct dev d;
    char error[96];
    BPTR fh;
    LONG len, s, err;
    int rc = RETURN_FAIL;

    if (state_load(&st)) {
        printf("WireGuard: a tunnel is already up; run WireGuard DOWN first\n");
        return RETURN_WARN;
    }
    fh = Open(file, MODE_OLDFILE);
    if (!fh) {
        printf("WireGuard: cannot open %s\n", file);
        return RETURN_FAIL;
    }
    len = Read(fh, text, sizeof(text));
    Close(fh);
    if (len <= 0 || !wg_config_parse(text, (size_t)len, &cfg, error, sizeof(error))) {
        memset(text, 0, sizeof(text));
        printf("WireGuard: %s: %s\n", file, len <= 0 ? "empty or unreadable" : error);
        return RETURN_FAIL;
    }
    memset(text, 0, sizeof(text));

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        printf("WireGuard: no socket, is the network running?\n");
        goto out;
    }

    memset(&st, 0, sizeof(st));
    st.magic = STATE_MAGIC;
    st.address = cfg.address;
    if (!wg_parse_ipv4(cfg.endpoint_host, &st.endpoint)) {
        struct hostent *h = gethostbyname(cfg.endpoint_host);
        if (!h || h->h_addrtype != AF_INET) {
            printf("WireGuard: cannot resolve the endpoint %s\n", cfg.endpoint_host);
            goto out_socket;
        }
        memcpy(&st.endpoint, h->h_addr_list[0], 4);
    }
    /* A point-to-point interface wants a far-end address. Any address works; this one is the tunnel's first host. */
    {
        UBYTE *a = (UBYTE *)&st.address;
        st.peer = make_ip(a[0], a[1], a[2], a[3] == 1 ? 2 : 1);
    }

    if (!iface_exists(s)) {
        if (!iface_create() || !iface_exists(s)) {
            printf("WireGuard: the stack did not take the interface " IFACE "; check " INTERFACES_FILE "\n");
            goto out_socket;
        }
        printf("WireGuard: interface " IFACE " added to the stack\n");
    }
    if (!dev_open(&d)) {
        printf("WireGuard: cannot open " WG_DEVICE_NAME "\n");
        dev_close(&d);
        goto out_socket;
    }

    memset(&dc, 0, sizeof(dc));
    memcpy(dc.private_key, cfg.private_key, 32);
    memcpy(dc.public_key, cfg.public_key, 32);
    memcpy(dc.preshared_key, cfg.preshared_key, 32);
    dc.has_preshared_key = cfg.has_preshared_key;
    dc.listen_port = cfg.listen_port;
    dc.endpoint_ip = st.endpoint;
    dc.endpoint_port = cfg.endpoint_port;
    dc.keepalive = cfg.keepalive;
    dc.allowed_count = (UBYTE)cfg.allowed_count;
    for (int i = 0; i < cfg.allowed_count; i++) {
        dc.allowed[i].ip = cfg.allowed[i].ip;
        dc.allowed[i].mask = cfg.allowed[i].mask;
    }

    /* The endpoint keeps its present path before any route points into the tunnel. */
    st.gateway = route_gateway(st.endpoint);
    if (st.gateway && !noroute) {
        err = route_change(RTM_ADD, st.endpoint, 0xffffffffu, st.gateway, TRUE);
        if (err == 0) {
            st.host_route = 1;
        } else if (err != EEXIST) {
            printf("WireGuard: cannot pin the route to the endpoint (error %ld)\n", (long)err);
            goto out_device;
        }
    }

    err = dev_command(&d, WGCMD_SETCONFIG, &dc, sizeof(dc));
    memset(&dc, 0, sizeof(dc));
    if (err != 0) {
        printf("WireGuard: the device refused the configuration (error %ld)\n", (long)err);
        goto out_device;
    }
    if (!iface_address(s, st.address, st.peer, TRUE) || !iface_flags(s, TRUE)) {
        printf("WireGuard: cannot set the address of " IFACE " (error %ld)\n", (long)Errno());
        tear_down(&d, s, &st);
        goto out_device;
    }
    if (!noroute) {
        for (int i = 0; i < cfg.allowed_count; i++) {
            ULONG ip = cfg.allowed[i].ip, mask = cfg.allowed[i].mask;
            /* Two halves stand in for 0.0.0.0/0, so the existing default route stays for DOWN to find. */
            int halves = mask == 0 ? 2 : 1;
            for (int h = 0; h < halves; h++) {
                ULONG rip = mask == 0 ? make_ip(h ? 128 : 0, 0, 0, 0) : ip;
                ULONG rmask = mask == 0 ? make_ip(128, 0, 0, 0) : mask;
                err = route_change(RTM_ADD, rip, rmask, st.peer, FALSE);
                if (err != 0 && err != EEXIST) {
                    printf("WireGuard: cannot add a route through " IFACE " (error %ld)\n", (long)err);
                    tear_down(&d, s, &st);
                    goto out_device;
                }
                st.route[st.routes].ip = rip;
                st.route[st.routes].mask = rmask;
                st.routes++;
            }
        }
    }
    if (!nodns && cfg.dns_count > 0) {
        dns_set(&cfg);
        st.dns_set = 1;
    }
    state_save(&st);

    printf("WireGuard: " IFACE " up, address ");
    print_ip(st.address);
    printf(", %lu route%s", (unsigned long)st.routes, st.routes == 1 ? "" : "s");
    if (cfg.skipped_ipv6) {
        printf(", %d IPv6 value%s of the file left out", cfg.skipped_ipv6, cfg.skipped_ipv6 == 1 ? "" : "s");
    }
    printf("\n");
    rc = RETURN_OK;

out_device:
    dev_close(&d);
out_socket:
    CloseSocket(s);
out:
    wg_config_wipe(&cfg);
    return rc;
}

static int command_down(void) {
    struct wg_state st;
    struct dev d;
    LONG s;

    if (!state_load(&st)) {
        printf("WireGuard: no tunnel is up\n");
        return RETURN_WARN;
    }
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0 || !dev_open(&d)) {
        printf("WireGuard: cannot reach the stack or the device\n");
        if (s >= 0) {
            CloseSocket(s);
            dev_close(&d);
        }
        return RETURN_FAIL;
    }
    tear_down(&d, s, &st);
    dev_close(&d);
    CloseSocket(s);
    if (st.dns_set) {
        /* The stack reads its configuration again, which restores the name servers it had. */
        stack_reload();
    }
    printf("WireGuard: " IFACE " down, keys wiped\n");
    return RETURN_OK;
}

static int command_status(void) {
    struct WGDeviceStatus status;
    struct dev d;

    if (!dev_open(&d)) {
        printf("WireGuard: cannot open " WG_DEVICE_NAME "\n");
        dev_close(&d);
        return RETURN_FAIL;
    }
    memset(&status, 0, sizeof(status));
    if (dev_command(&d, WGCMD_GETSTATUS, &status, sizeof(status)) != 0) {
        printf("WireGuard: the device did not answer\n");
        dev_close(&d);
        return RETURN_FAIL;
    }
    dev_close(&d);
    printf("[WG] configured=%d up=%d online=%d socket=%d socket-errno=%ld handshake-age=%ld handshakes=%lu/%lu "
           "tx=%llu rx=%llu tx-bytes=%llu rx-bytes=%llu bad-auth=%llu replayed=%llu bad-source=%llu malformed=%llu "
           "no-session=%llu no-reader=%llu send-errors=%llu\n",
           status.configured, status.up, status.online, status.socket_state, (long)status.socket_errno,
           (long)status.handshake_age, (unsigned long)status.handshakes_completed, (unsigned long)status.handshakes_sent,
           (unsigned long long)status.tx_packets, (unsigned long long)status.rx_packets,
           (unsigned long long)status.tx_bytes, (unsigned long long)status.rx_bytes,
           (unsigned long long)status.rx_bad_auth, (unsigned long long)status.rx_replayed,
           (unsigned long long)status.rx_bad_source, (unsigned long long)status.rx_malformed,
           (unsigned long long)status.tx_no_session, (unsigned long long)status.rx_no_reader,
           (unsigned long long)status.udp_send_errors);
    return status.up ? RETURN_OK : RETURN_WARN;
}

static int command_exitip(void) {
    static const char host[] = "api.ipify.org";
    static const char request[] = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\nUser-Agent: wireguard-aros\r\n\r\n";
    static char reply[2048];
    struct hostent *h = gethostbyname((char *)host);
    struct sockaddr_in to;
    LONG s, n, total = 0;
    char *body;

    if (!h || h->h_addrtype != AF_INET) {
        printf("[WG] FAIL exitip: cannot resolve %s\n", host);
        return RETURN_FAIL;
    }
    in_addr_set((struct sockaddr *)&to, 0);
    memcpy(&to.sin_addr.s_addr, h->h_addr_list[0], 4);
    to.sin_port = htons(80);
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0 || connect(s, (struct sockaddr *)&to, sizeof(to)) < 0 ||
        send(s, (char *)request, sizeof(request) - 1, 0) < 0) {
        printf("[WG] FAIL exitip: resolved, cannot connect (error %ld)\n", (long)Errno());
        if (s >= 0) {
            CloseSocket(s);
        }
        return RETURN_FAIL;
    }
    while (total < (LONG)sizeof(reply) - 1 && (n = recv(s, reply + total, sizeof(reply) - 1 - total, 0)) > 0) {
        total += n;
    }
    CloseSocket(s);
    reply[total] = 0;
    body = strstr(reply, "\r\n\r\n");
    if (!body || strncmp(reply, "HTTP/1.", 7) != 0 || strncmp(reply + 9, "200", 3) != 0) {
        printf("[WG] FAIL exitip: unexpected answer\n");
        return RETURN_FAIL;
    }
    body += 4;
    body[strcspn(body, "\r\n ")] = 0;
    printf("[WG] PASS exitip=%s resolved=1\n", body);
    return RETURN_OK;
}

int main(void) {
    static const char template[] = "UP/S,DOWN/S,STATUS/S,EXITIP/S,FILE/K,NOROUTE/S,NODNS/S";
    IPTR args[7] = {0, 0, 0, 0, 0, 0, 0};
    struct RDArgs *rd = ReadArgs((STRPTR)template, args, NULL);
    int rc = RETURN_FAIL;

    if (!rd) {
        printf("usage: WireGuard UP FILE <file> [NOROUTE] [NODNS] | DOWN | STATUS | EXITIP\n");
        return RETURN_FAIL;
    }
    if (args[2]) {
        rc = command_status();
    } else {
        SocketBase = OpenLibrary("bsdsocket.library", 4);
        if (!SocketBase) {
            printf("WireGuard: no bsdsocket.library, the network is not running\n");
        } else {
            if (args[0] && args[4]) {
                rc = command_up((const char *)args[4], args[5] != 0, args[6] != 0);
            } else if (args[1]) {
                rc = command_down();
            } else if (args[3]) {
                rc = command_exitip();
            } else {
                printf("usage: WireGuard UP FILE <file> [NOROUTE] [NODNS] | DOWN | STATUS | EXITIP\n");
            }
            CloseLibrary(SocketBase);
        }
    }
    FreeArgs(rd);
    return rc;
}
