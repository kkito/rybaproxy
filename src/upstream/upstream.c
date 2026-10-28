#include "rybaproxy/upstream.h"
#include "rybaproxy/dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_timeout_fd(int fd, const struct sockaddr *sa, socklen_t slen, int sec) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (connect(fd, sa, slen) == 0) {
        fcntl(fd, F_SETFL, flags);
        return 0;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv = { .tv_sec = sec, .tv_usec = 0 };
    int rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0) { close(fd); return -1; }
    int soerr = 0;
    socklen_t sl = sizeof soerr;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
    if (soerr != 0) { close(fd); return -1; }
    fcntl(fd, F_SETFL, flags);
    return 0;
}

static int tcp_connect_host(const char *host, uint16_t port, int sec) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%u", port);
    if (dns_getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect_timeout_fd(fd, ai->ai_addr, ai->ai_addrlen, sec) == 0) break;
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int upstream_connect_direct(const char *host, uint16_t port, int *out_fd) {
    int fd = tcp_connect_host(host, port, 10);
    if (fd < 0) return -1;
    *out_fd = fd;
    return 0;
}

/* read until \r\n\r\n or buffer full */
static int read_http_response(int fd, char *buf, size_t cap) {
    size_t total = 0;
    while (total < cap - 1) {
        ssize_t n = recv(fd, buf + total, cap - 1 - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
        buf[total] = '\0';
        if (strstr(buf, "\r\n\r\n")) return 0;
    }
    return -1;
}

int upstream_connect_http(const upstream_profile_t *up, const char *target_host, uint16_t target_port, int *out_fd) {
    if (!up) return -1;
    int fd = tcp_connect_host(up->host, up->port, 10);
    if (fd < 0) return -1;
    char req[1024];
    int rlen;
    if (up->username[0]) {
        char creds[256];
        snprintf(creds, sizeof creds, "%s:%s", up->username, up->password);
        /* base64 encode minimal */
        /* use a simple base64 encoder */
        static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        char b64[512];
        size_t i, j = 0;
        size_t cl = strlen(creds);
        for (i = 0; i < cl; i += 3) {
            unsigned int v = (unsigned char)creds[i] << 16;
            if (i+1 < cl) v |= (unsigned char)creds[i+1] << 8;
            if (i+2 < cl) v |= (unsigned char)creds[i+2];
            b64[j++] = t[(v>>18)&63];
            b64[j++] = t[(v>>12)&63];
            b64[j++] = (i+1 < cl) ? t[(v>>6)&63] : '=';
            b64[j++] = (i+2 < cl) ? t[v&63] : '=';
        }
        b64[j] = '\0';
        rlen = snprintf(req, sizeof req,
            "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\nProxy-Authorization: Basic %s\r\n\r\n",
            target_host, target_port, target_host, target_port, b64);
    } else {
        rlen = snprintf(req, sizeof req,
            "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n",
            target_host, target_port, target_host, target_port);
    }
    if (send(fd, req, rlen, 0) < 0) { close(fd); return -1; }
    char resp[4096];
    if (read_http_response(fd, resp, sizeof resp) != 0) { close(fd); return -1; }
    if (strstr(resp, "200") == NULL) { close(fd); return -1; }
    *out_fd = fd;
    return 0;
}

int upstream_connect_socks5(const upstream_profile_t *up, const char *target_host, uint16_t target_port, int *out_fd) {
    if (!up) return -1;
    int fd = tcp_connect_host(up->host, up->port, 10);
    if (fd < 0) return -1;
    /* handshake: no auth or username/password */
    unsigned char buf[4];
    if (up->username[0]) {
        unsigned char hello[4] = {0x05,0x02,0x00,0x02};
        if (send(fd, hello, 4, 0) != 4) { close(fd); return -1; }
        unsigned char resp[2];
        if (recv(fd, resp, 2, 0) != 2 || resp[0] != 0x05 || resp[1] != 0x02) { close(fd); return -1; }
        /* auth */
        size_t ulen = strlen(up->username), plen = strlen(up->password);
        unsigned char abuf[512];
        abuf[0]=0x01;
        abuf[1]=(unsigned char)ulen;
        memcpy(abuf+2, up->username, ulen);
        abuf[2+ulen]=(unsigned char)plen;
        memcpy(abuf+3+ulen, up->password, plen);
        if (send(fd, abuf, 3+ulen+plen, 0) < 0) { close(fd); return -1; }
        unsigned char aresp[2];
        if (recv(fd, aresp, 2, 0) != 2 || aresp[1] != 0x00) { close(fd); return -1; }
    } else {
        unsigned char hello[3] = {0x05,0x01,0x00};
        if (send(fd, hello, 3, 0) != 3) { close(fd); return -1; }
        unsigned char resp[2];
        if (recv(fd, resp, 2, 0) != 2 || resp[0] != 0x05 || resp[1] != 0x00) { close(fd); return -1; }
    }
    /* CONNECT request */
    unsigned char req[512];
    size_t pos = 0;
    req[pos++]=0x05; req[pos++]=0x01; req[pos++]=0x00;
    /* atyp domain if not IP; try IP first */
    struct in_addr ia;
    if (inet_pton(AF_INET, target_host, &ia) == 1) {
        req[pos++]=0x01;
        memcpy(req+pos, &ia.s_addr, 4); pos+=4;
    } else {
        size_t hl = strlen(target_host);
        req[pos++]=0x03;
        req[pos++]=(unsigned char)hl;
        memcpy(req+pos, target_host, hl); pos+=hl;
    }
    req[pos++] = (unsigned char)(target_port >> 8);
    req[pos++] = (unsigned char)(target_port & 0xFF);
    if (send(fd, req, pos, 0) < 0) { close(fd); return -1; }
    unsigned char r[256];
    ssize_t rn = recv(fd, r, sizeof r, 0);
    if (rn < 2 || r[1] != 0x00) { close(fd); return -1; }
    *out_fd = fd;
    return 0;
}

#include <time.h>

/* 路由结果 → 上游下标（纯函数，无 IO）。
 * route_id >= 0：按 id 找启用项；找不到回落 direct；再找不到 -1。
 * route_id < 0（无规则命中）：按 default_name 找，空名取第一个启用项，回落 direct。 */
int upstream_pick(const upstream_profile_t *ups, int n, const char *default_name, int route_id) {
    if (!ups || n <= 0) return -1;
    if (route_id >= 0) {
        for (int i = 0; i < n; i++)
            if (ups[i].enabled && ups[i].id == route_id) return i;
    } else if (default_name && default_name[0]) {
        for (int i = 0; i < n; i++)
            if (ups[i].enabled && strcmp(ups[i].name, default_name) == 0) return i;
    } else {
        for (int i = 0; i < n; i++) if (ups[i].enabled) return i;
    }
    for (int i = 0; i < n; i++)
        if (ups[i].enabled && ups[i].type == UPSTREAM_DIRECT) return i;
    return -1;
}

int upstream_test_reachable(const upstream_profile_t *up, int timeout_ms, long *latency_ms_out) {
    if (latency_ms_out) *latency_ms_out = -1;
    if (!up) return -1;
    if (up->type == UPSTREAM_DIRECT) {
        if (latency_ms_out) *latency_ms_out = 0;
        return 0;
    }
    if (!up->host[0] || up->port == 0) return -1;
    if (timeout_ms <= 0) timeout_ms = 3000;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%u", up->port);
    if (dns_getaddrinfo(up->host, portstr, &hints, &res) != 0 || !res) return -1;
    int sec = timeout_ms / 1000;
    int msec = timeout_ms % 1000;
    int ok = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        struct timeval tv = { .tv_sec = sec, .tv_usec = msec * 1000 };
        int rc;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) rc = 0;
        else if (errno != EINPROGRESS) rc = -1;
        else {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            rc = select(fd + 1, NULL, &wfds, NULL, &tv);
            if (rc > 0) {
                int soerr = 0;
                socklen_t sl = sizeof soerr;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
                rc = (soerr == 0) ? 1 : -1;
            } else rc = -1;
        }
        close(fd);
        if (rc >= 0) { ok = 0; break; }
    }
    freeaddrinfo(res);
    if (ok == 0 && latency_ms_out) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *latency_ms_out = (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
    }
    return ok;
}
