#ifndef RYBAPROXY_CONFIG_H
#define RYBAPROXY_CONFIG_H

#include "rybaproxy/common.h"
#include <stdlib.h>

#define RYBA_NAME_MAX 128

typedef struct {
    int http_port;
    int socks5_port;
    int web_port;
    int max_connections;
    int idle_timeout_sec;
    int max_session_sec;
    int connect_timeout_sec;
    int dns_timeout_sec;
    bool proxy_auth_enabled;
    char proxy_username[RYBA_NAME_MAX];
    char proxy_password[RYBA_NAME_MAX];
    char default_upstream[RYBA_NAME_MAX];
    bool fallback_to_direct;
    bool resolve_for_routing;
    char db_path[512];
    char geo_dir[512];
    int retention_days;
    upstream_profile_t *upstreams;
    int upstream_count;
} config_t;

void config_init_defaults(config_t *c);
int config_load(const char *path, config_t *c);
void config_free(config_t *c);

#endif
