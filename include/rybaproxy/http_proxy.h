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

/* host[:port] 拆分（纯函数，零依赖）。
 * 支持 [v6]:port / [v6] / 裸 v6 / host:port / host；无端口时用 default_port。
 * IPv6 字面量去掉方括号写回 host（拿去做 getaddrinfo/统计都干净）。
 * 返回 0 成功，-1 输入为空或 host 装不下。 */
int parse_hostport(const char *src, char *host, size_t hostsz, uint16_t *port, uint16_t default_port);

/* host:port 拼回字符串（纯函数）：IPv6 字面量自动加方括号，
 * 否则 CONNECT 2401:67c::1:443 是坏请求。 */
void format_hostport(const char *host, uint16_t port, char *out, size_t outsz);

#endif
