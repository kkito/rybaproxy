#ifndef RYBAPROXY_UPSTREAM_H
#define RYBAPROXY_UPSTREAM_H

#include "rybaproxy/common.h"
#include <event2/event.h>

int upstream_connect_direct(const char *host, uint16_t port, int *out_fd);
int upstream_connect_http(const upstream_profile_t *up, const char *target_host, uint16_t target_port, int *out_fd);
int upstream_connect_socks5(const upstream_profile_t *up, const char *target_host, uint16_t target_port, int *out_fd);
/* 路由结果 → 上游下标（纯函数，无 IO）：route_id<0 表示无规则命中 */
int upstream_pick(const upstream_profile_t *ups, int n, const char *default_name, int route_id);
/* TCP reachability probe: 0 = reachable, nonzero = unreachable. direct always 0. */
int upstream_test_reachable(const upstream_profile_t *up, int timeout_ms, long *latency_ms_out);

#endif
