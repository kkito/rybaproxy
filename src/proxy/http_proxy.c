#include "rybaproxy/http_proxy.h"

#include <llhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    /* determine host/port */
    if (info->is_connect) {
        /* CONNECT target is in URL host:port */
        char tmp[256];
        snprintf(tmp, sizeof tmp, "%s", info->url);
        char *colon = strchr(tmp, ':');
        if (colon) {
            *colon = '\0';
            info->port = (uint16_t)atoi(colon + 1);
        } else {
            info->port = 443;
        }
        snprintf(info->host, sizeof info->host, "%s", tmp);
    } else {
        /* absolute URI? parse host from url if present */
        if (strncmp(info->url, "http://", 7) == 0 || strncmp(info->url, "https://", 8) == 0) {
            int ssl = (strncmp(info->url, "https://", 8) == 0);
            char *p = info->url + (ssl ? 8 : 7);
            char tmp[2048];
            snprintf(tmp, sizeof tmp, "%s", p);
            char *slash = strchr(tmp, '/');
            if (slash) *slash = '\0';
            char *colon = strchr(tmp, ':');
            if (colon) {
                *colon = '\0';
                info->port = (uint16_t)atoi(colon + 1);
            } else {
                info->port = ssl ? 443 : 80;
            }
            snprintf(info->host, sizeof info->host, "%s", tmp);
        }
        if (info->host[0] == '\0' && ctx.field[0]) {
            /* host header already captured */
        }
        /* if host header has port */
        char *colon = strchr(info->host, ':');
        if (colon && info->port == 80) {
            *colon = '\0';
            info->port = (uint16_t)atoi(colon + 1);
        }
    }
    if (info->host[0] == '\0') {
        /* fallback to host header (may include port) */
        snprintf(info->host, sizeof info->host, "%s", info->host);
    }
    return 0;
}
