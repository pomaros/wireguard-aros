/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * wgprobe CONFIG [NAME]
 *
 * Brings a WireGuard tunnel up from a configuration file on a POSIX host,
 * with no kernel interface, and resolves NAME (default: example.com) by
 * sending one DNS query inside the tunnel to the DNS server of the file.
 * It proves that the engine interoperates with the peer's implementation.
 * The last line is the verdict. Keys and addresses are never printed.
 */
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "wg_config.h"
#include "wg_tunnel.h"

struct probe {
    int fd;
    uint16_t dns_id;
    uint32_t dns_server;
    int answers;
    int reply_seen;
    uint8_t first_a[4];
};

static int udp_send(void *ctx, const uint8_t *data, size_t len, uint32_t ip, uint16_t port) {
    struct probe *p = ctx;
    struct sockaddr_in to;

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ip;
    to.sin_port = htons(port);
    return sendto(p->fd, data, len, 0, (struct sockaddr *)&to, sizeof(to)) == (ssize_t)len ? 0 : -1;
}

static void ip_input(void *ctx, const uint8_t *packet, size_t len) {
    struct probe *p = ctx;
    size_t hlen = (size_t)(packet[0] & 0x0f) * 4;
    uint32_t src;

    memcpy(&src, packet + 12, 4);
    if (packet[9] != 17 || src != p->dns_server || len < hlen + 8 + 12) {
        return;
    }
    const uint8_t *dns = packet + hlen + 8;
    size_t dns_len = len - hlen - 8;
    if (((dns[0] << 8) | dns[1]) != p->dns_id || !(dns[2] & 0x80)) {
        return;
    }
    p->reply_seen = 1;
    p->answers = (dns[6] << 8) | dns[7];

    /* Skip the question, then walk the answers for the first A record. */
    size_t pos = 12;
    while (pos < dns_len && dns[pos] != 0) {
        pos += (size_t)dns[pos] + 1;
    }
    pos += 5;
    for (int i = 0; i < p->answers && pos + 12 <= dns_len; i++) {
        if ((dns[pos] & 0xc0) == 0xc0) {
            pos += 2;
        } else {
            while (pos < dns_len && dns[pos] != 0) {
                pos += (size_t)dns[pos] + 1;
            }
            pos += 1;
        }
        if (pos + 10 > dns_len) {
            break;
        }
        unsigned type = (unsigned)((dns[pos] << 8) | dns[pos + 1]);
        size_t rdlen = (size_t)((dns[pos + 8] << 8) | dns[pos + 9]);
        pos += 10;
        if (type == 1 && rdlen == 4 && pos + 4 <= dns_len) {
            memcpy(p->first_a, dns + pos, 4);
            return;
        }
        pos += rdlen;
    }
}

static uint16_t checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;

    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    }
    if (len & 1) {
        sum += (uint32_t)(data[len - 1] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static size_t dns_query_packet(uint8_t *p, uint32_t src, uint32_t dst, uint16_t id, const char *name) {
    uint8_t *dns = p + 28;
    size_t n = 12;

    memset(p, 0, 28 + 12);
    dns[0] = (uint8_t)(id >> 8); dns[1] = (uint8_t)id;
    dns[2] = 0x01;              /* recursion desired */
    dns[5] = 1;                 /* one question */
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t label = dot ? (size_t)(dot - name) : strlen(name);
        dns[n++] = (uint8_t)label;
        memcpy(dns + n, name, label);
        n += label;
        name += label + (dot ? 1 : 0);
    }
    dns[n++] = 0;
    dns[n++] = 0; dns[n++] = 1; /* type A */
    dns[n++] = 0; dns[n++] = 1; /* class IN */

    size_t udp_len = 8 + n, total = 20 + udp_len;
    p[0] = 0x45;
    p[2] = (uint8_t)(total >> 8); p[3] = (uint8_t)total;
    p[8] = 64; p[9] = 17;
    memcpy(p + 12, &src, 4);
    memcpy(p + 16, &dst, 4);
    uint16_t sum = checksum(p, 20);
    p[10] = (uint8_t)(sum >> 8); p[11] = (uint8_t)sum;
    p[20] = 0xc3; p[21] = 0x50;   /* source port 50000 */
    p[22] = 0; p[23] = 53;
    p[24] = (uint8_t)(udp_len >> 8); p[25] = (uint8_t)udp_len;
    /* UDP checksum 0: optional over IPv4. */
    return total;
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    static struct wg_tunnel tunnel;
    static const struct wg_tunnel_ops ops = {udp_send, ip_input};
    static char text[8192];
    struct wg_config cfg;
    struct probe probe;
    char error[96];
    const char *name = argc > 2 ? argv[2] : "example.com";
    uint32_t endpoint;
    uint8_t index, buffer[2048];

    if (argc < 2) {
        fprintf(stderr, "usage: wgprobe CONFIG [NAME]\n");
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return 2;
    }
    size_t len = fread(text, 1, sizeof(text), f);
    fclose(f);
    if (!wg_config_parse(text, len, &cfg, error, sizeof(error))) {
        memset(text, 0, sizeof(text));
        printf("[WGPROBE] FAIL config: %s\n", error);
        return 1;
    }
    memset(text, 0, sizeof(text));
    if (cfg.dns_count == 0) {
        printf("[WGPROBE] FAIL config: no IPv4 DNS server to query\n");
        return 1;
    }
    if (!wg_parse_ipv4(cfg.endpoint_host, &endpoint)) {
        struct hostent *h = gethostbyname(cfg.endpoint_host);
        if (!h || h->h_addrtype != AF_INET) {
            printf("[WGPROBE] FAIL endpoint: cannot resolve the endpoint name\n");
            return 1;
        }
        memcpy(&endpoint, h->h_addr_list[0], 4);
    }

    memset(&probe, 0, sizeof(probe));
    probe.fd = socket(AF_INET, SOCK_DGRAM, 0);
    probe.dns_server = cfg.dns[0];
    probe.dns_id = (uint16_t)(now_ms() ^ getpid());

    if (wg_tunnel_init(&tunnel, cfg.private_key, &ops, &probe) != WG_OK ||
        wg_tunnel_add_peer(&tunnel, cfg.public_key, cfg.has_preshared_key ? cfg.preshared_key : NULL, endpoint,
                           cfg.endpoint_port, cfg.keepalive, &index) != WG_OK) {
        printf("[WGPROBE] FAIL init\n");
        return 1;
    }
    for (int i = 0; i < cfg.allowed_count; i++) {
        wg_tunnel_allow(&tunnel, index, cfg.allowed[i].ip, cfg.allowed[i].mask);
    }
    uint32_t address = cfg.address;
    wg_config_wipe(&cfg);
    wg_tunnel_connect(&tunnel, index);

    long start = now_ms(), up_at = -1, reply_at = -1, last_query = 0;
    int queries = 0;
    while (now_ms() - start < 15000 && !probe.reply_seen) {
        struct pollfd pfd = {probe.fd, POLLIN, 0};
        if (poll(&pfd, 1, WG_TUNNEL_TICK_MSECS / 4) > 0) {
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            ssize_t n = recvfrom(probe.fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_len);
            if (n > 0) {
                wg_tunnel_udp_input(&tunnel, buffer, (size_t)n, from.sin_addr.s_addr, ntohs(from.sin_port));
            }
        }
        wg_tunnel_tick(&tunnel);
        if (wg_tunnel_is_up(&tunnel)) {
            if (up_at < 0) {
                up_at = now_ms() - start;
            }
            if (queries < 5 && now_ms() - last_query > 1000) {
                size_t qlen = dns_query_packet(buffer, address, probe.dns_server, probe.dns_id, name);
                wg_tunnel_output(&tunnel, buffer, qlen);
                last_query = now_ms();
                queries++;
            }
        }
    }
    if (probe.reply_seen) {
        reply_at = now_ms() - start;
    }
    int has_a = probe.first_a[0] | probe.first_a[1] | probe.first_a[2] | probe.first_a[3];
    printf("[WGPROBE] %s handshake=%d handshake-ms=%ld initiations=%u dns-reply=%d reply-ms=%ld answers=%d name=%s",
           (up_at >= 0 && probe.reply_seen && has_a) ? "PASS" : "FAIL", up_at >= 0, up_at,
           tunnel.stats.handshakes_sent, probe.reply_seen, reply_at, probe.answers, name);
    if (has_a) {
        printf(" a=%u.%u.%u.%u", probe.first_a[0], probe.first_a[1], probe.first_a[2], probe.first_a[3]);
    }
    printf(" rx-bad-auth=%llu\n", (unsigned long long)tunnel.stats.rx_bad_auth);
    wg_tunnel_shutdown(&tunnel);
    close(probe.fd);
    return (up_at >= 0 && probe.reply_seen && has_a) ? 0 : 1;
}
