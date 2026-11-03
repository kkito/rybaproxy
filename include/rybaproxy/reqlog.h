#ifndef RYBAPROXY_REQLOG_H
#define RYBAPROXY_REQLOG_H

#include <stddef.h>
#include <stdint.h>

/* 请求日志格式化：全是无状态纯函数（输入 → 一行文本），
 * 采样/落盘交给调用方的薄胶水。便于单测断言格式，也便于事后 grep 日志。 */

typedef struct {
    uint64_t id;
    const char *client;
    const char *host;
    uint16_t port;
    const char *proto;     /* "HTTP" / "SOCKS5" */
    const char *method;    /* 可空 */
    int rule_id;           /* -1 = 没命中规则（走默认上游） */
    const char *rule_name; /* 可空 */
    const char *upstream;  /* 最终选中的上游名 */
    int geo_site;          /* 1=在 geosite-cn, 0=不在, -1=没查 */
    int geo_host;          /* 1=解析到 CN IP, 0=不是, -1=没查 */
    int geo_lan;           /* 1=内网, 0=不是, -1=没查 */
} reqlog_route_t;

size_t reqlog_format_route(char *out, size_t cap, const reqlog_route_t *r);
size_t reqlog_format_connect(char *out, size_t cap, uint64_t id, const char *upstream,
                             int ok, long ms, const char *err);
size_t reqlog_format_finish(char *out, size_t cap, uint64_t id, const char *host, uint16_t port,
                            int status, long dur_ms, uint64_t up, uint64_t down, const char *err);

#endif
