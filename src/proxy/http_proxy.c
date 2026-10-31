#include "rybaproxy/http_proxy.h"

#include <llhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strncasecmp：POSIX 声明在 strings.h，macOS 的 string.h 顺带暴露
                        * 会掩盖漏 include，Linux 严格 -std=c11 下直接编不过 */

typedef struct {
    http_request_info_t *info;
    int in_host;
    char field[64];
} ctx_t;

static int on_url(llhttp_t *p, const char *at, size_t length) {
    ctx_t *c = (ctx_t*)p->data;
    size_t n = length < sizeof c->info->url - 1 ? length : sizeof c->info->url - 1;
    memcpy(c->info->url, at, n);
    c->info->url[n] = '\0';
    return 0;
}

static int on_header_field(llhttp_t *p, const char *at, size_t length) {
    ctx_t *c = (ctx_t*)p->data;
    size_t n = length < sizeof c->field - 1 ? length : sizeof c->field - 1;
    memcpy(c->field, at, n);
    c->field[n] = '\0';
    c->in_host = (strncasecmp(c->field, "host", 4) == 0 && length == 4);
    return 0;
}

static int on_header_value(llhttp_t *p, const char *at, size_t length) {
    ctx_t *c = (ctx_t*)p->data;
    if (c->in_host && c->info->host[0] == '\0') {
        size_t n = length < sizeof c->info->host - 1 ? length : sizeof c->info->host - 1;
        memcpy(c->info->host, at, n);
        c->info->host[n] = '\0';
    }
    return 0;
}

int parse_hostport(const char *src, char *host, size_t hostsz, uint16_t *port, uint16_t default_port) {
    if (!src || !host || !port || hostsz == 0) return -1;
    const char *h = src;
    size_t hlen;
    *port = default_port;
    host[0] = '\0';
    while (*h == ' ') h++;
    if (*h == '\0') return -1;

    if (*h == '[') {
        /* [v6] 或 [v6]:port */
        const char *close = strchr(h + 1, ']');
        if (!close) return -1;
        hlen = (size_t)(close - (h + 1));
        h += 1;
        if (close[1] == ':') *port = (uint16_t)atoi(close + 2);
    } else {
        const char *last = strrchr(h, ':');
        if (last && strchr(h, ':') == last) {
            /* 恰好一个冒号：host:port；冒号后不是数字就当整个串是 host */
            int digits = last[1] != '\0';
            for (const char *p = last + 1; *p; p++) if (*p < '0' || *p > '9') { digits = 0; break; }
            if (digits) {
                hlen = (size_t)(last - h);
                *port = (uint16_t)atoi(last + 1);
            } else {
                hlen = strlen(h);
            }
        } else {
            /* 无冒号，或裸 IPv6（多冒号，不带端口） */
            hlen = strlen(h);
        }
    }
    if (hlen == 0 || hlen >= hostsz) return -1;
    memcpy(host, h, hlen);
    host[hlen] = '\0';
    return 0;
}

void format_hostport(const char *host, uint16_t port, char *out, size_t outsz) {
    if (!out || outsz == 0) return;
    if (!host) host = "";
    if (strchr(host, ':')) snprintf(out, outsz, "[%s]:%u", host, port);
    else snprintf(out, outsz, "%s:%u", host, port);
}

int http_proxy_parse_request(const char *buf, size_t len, http_request_info_t *info) {
    if (!buf || !info) return -1;
    memset(info, 0, sizeof *info);
    info->port = 80;

    llhttp_t parser;
    llhttp_settings_t settings;
    llhttp_settings_init(&settings);
    settings.on_url = on_url;
    settings.on_header_field = on_header_field;
    settings.on_header_value = on_header_value;

    llhttp_init(&parser, HTTP_REQUEST, &settings);
    ctx_t ctx = { .info = info, .in_host = 0 };
    parser.data = &ctx;

    enum llhttp_errno err = llhttp_execute(&parser, buf, len);
    if (err != HPE_OK && err != HPE_PAUSED_UPGRADE) {
        return -1;
    }

    /* method */
    const char *mname = llhttp_method_name(parser.method);
    snprintf(info->method, sizeof info->method, "%s", mname);
    info->is_connect = (parser.method == HTTP_CONNECT);

    /* 取 host:port 的来源 + 默认端口：
     *   CONNECT   → URL 就是 authority，默认 443
     *   绝对 URI    → URL 里的 authority，http=80 / https=443
     *   origin-form → Host 头，默认 80
     * 交给 parse_hostport 统一处理方括号 IPv6（否则 [2401:...]:443 会被
     * 第一个冒号砍成 host="[2401" port=67）。 */
    char hp[2048];
    uint16_t dflt = 80;
    hp[0] = '\0';
    if (info->is_connect) {
        snprintf(hp, sizeof hp, "%s", info->url);
        dflt = 443;
    } else if (strncmp(info->url, "http://", 7) == 0 || strncmp(info->url, "https://", 8) == 0) {
        int ssl = (strncmp(info->url, "https://", 8) == 0);
        snprintf(hp, sizeof hp, "%s", info->url + (ssl ? 8 : 7));
        char *slash = strchr(hp, '/');
        if (slash) *slash = '\0';
        char *q = strchr(hp, '?');
        if (q) *q = '\0';
        dflt = ssl ? 443 : 80;
    } else {
        snprintf(hp, sizeof hp, "%s", info->host); /* Host 头 */
        dflt = 80;
    }

    char hostbuf[256];
    uint16_t port = dflt;
    if (parse_hostport(hp, hostbuf, sizeof hostbuf, &port, dflt) != 0) return -1;
    snprintf(info->host, sizeof info->host, "%s", hostbuf);
    info->port = port;
    return 0;
}
