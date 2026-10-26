#ifndef RYBAPROXY_UPSTREAM_H
#define RYBAPROXY_UPSTREAM_H

#include "rybaproxy/common.h"
#include <event2/event.h>

int upstream_connect_direct(const char *host, uint16_t port, int *out_fd);
int upstream_connect_http(const upstream_profile_t *up, const char *target_host, uint16_t target_port, int *out_fd);
int upstream_connect_socks5(const upstream_profile_t *up, const char *target_host, uint16_t target_port, int *out_fd);

#endif
