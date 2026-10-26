#ifndef RYBAPROXY_HTTP_PROXY_H
#define RYBAPROXY_HTTP_PROXY_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char method[16];
    char url[2048];
    char host[256];
    uint16_t port;
    int is_connect;
} http_request_info_t;

/* Parse a single HTTP request from buf. Returns 0 on success. */
int http_proxy_parse_request(const char *buf, size_t len, http_request_info_t *info);

#endif
