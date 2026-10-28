#ifndef RYBAPROXY_DNS_H
#define RYBAPROXY_DNS_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* 可注入解析器（测试用）。返回 0 表示成功并将第一个 IP 写入 ip_out（空串终止）。
 * NULL = 使用系统 getaddrinfo。*/
typedef int (*dns_resolver_fn)(const char *host, char *ip_out, size_t ipsz);

void dns_init(void);
void dns_set_resolver(dns_resolver_fn fn);
/* 当前注入的 resolver（NULL=系统） */
void *dns_test_get_resolver(void);
/* 超时（秒），<=0 使用默认 */
void dns_set_timeout_sec(int sec);
int dns_timeout_sec(void);

/* 解析首个 IP（AF_UNSPEC，SOCK_STREAM）。返回 0 成功。 */
int dns_resolve_first(const char *host, const char *serv, char *ip_out, size_t ipsz);

/* 获取完整 addrinfo 链（用于 upstream 遍历 ai_next）。调用方需 freeaddrinfo。
 * 注入 resolver 存在时，可能退化为仅返回首个结果的链（行为等价于“遍历首个可用”），
 * 但默认走系统实现以保留原有遍历逻辑。 */
int dns_getaddrinfo(const char *host, const char *serv,
                    const struct addrinfo *hints, struct addrinfo **res);

#endif
