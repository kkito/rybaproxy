#ifndef RYBAPROXY_SERVER_H
#define RYBAPROXY_SERVER_H

#include "rybaproxy/config.h"
#include "rybaproxy/router.h"
#include "rybaproxy/upstream.h"
#include <event2/event.h>

typedef struct server_ctx {
    struct event_base *base;
    config_t config;
    router_t router;
    upstream_profile_t *upstreams;
    int upstream_count;
    int http_listener_fd;
    int socks_listener_fd;
    struct event *http_ev;
    struct event *socks_ev;
} server_ctx_t;

int server_init(server_ctx_t *ctx, const config_t *cfg);
int server_run(server_ctx_t *ctx);
void server_free(server_ctx_t *ctx);

#endif
