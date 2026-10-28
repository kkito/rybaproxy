#ifndef RYBAPROXY_DNS_H
#define RYBAPROXY_DNS_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>

/* 可注入解析器（测试用）。返回 0 表示成功并将第一个 IP 写入 ip_out（空串终止）。
 * NULL = 使用系统 getaddrinfo。*/
typedef int (*dns_resolver_fn)(const char *host, char *ip_out, size_t ipsz);

typedef enum { DNS_CLASS_AUTO = 0, DNS_CLASS_DOMESTIC = 1, DNS_CLASS_FOREIGN = 2 } dns_class_t;
typedef enum { DNS_NS_DOH = 0, DNS_NS_UDP = 1 } dns_ns_type_t;

typedef struct {
    dns_ns_type_t type;
    char url[256];
    char host[256];
    char server_ips[4][64];
    int server_ip_n;
    char proxy[64]; /* none|upstream:<id>|inherit */
} dns_ns_t;

typedef struct {
    char domain[256];
    dns_class_t class;
    char resolver_id[64];
    char ips[4][64];
    int ip_n;
    int ttl;
    int ttl_eff;
    time_t expire_at;
    time_t last_used;
    unsigned int hits;
    bool negative;
} dns_cache_entry_t;

typedef struct {
    time_t ts;
    char domain[256];
    dns_class_t class;
    char resolver_id[64];
    bool via_proxy;
    long duration_ms;
    char status[16]; /* ok|timeout|fail|nxdomain */
    int ip_count;
    bool from_cache;
} dns_req_log_t;

typedef struct {
    char ips[4][64];
    int ip_n;
    int ttl;
    dns_class_t class;
    char resolver_id[64];
    bool from_cache;
} dns_result_t;

void dns_init(void);
void dns_set_resolver(dns_resolver_fn fn);
/* 当前注入的 resolver（NULL=系统） */
void *dns_test_get_resolver(void);
/* 超时（秒），<=0 使用默认 */
void dns_set_timeout_sec(int sec);
int dns_timeout_sec(void);

/* 解析首个 IP（AF_UNSPEC，SOCK_STREAM）。返回 0 成功。 */
int dns_resolve_first(const char *host, const char *serv, char *ip_out, size_t ipsz);

/* 获取完整 addrinfo 链（用于 upstream 遍历 ai_next）。调用方需 freeaddrinfo。 */
int dns_getaddrinfo(const char *host, const char *serv,
                    const struct addrinfo *hints, struct addrinfo **res);

/* 增强版本接口（保持向后兼容） */
int dns_resolve(const char *domain, dns_class_t cls, dns_result_t *out);
int dns_set_proxy(const char *spec);
const char *dns_get_proxy(void);
int dns_set_nameservers(const dns_ns_t *list, size_t n);
int dns_add_nameserver(const dns_ns_t *ns);
int dns_clear_nameservers(void);
int dns_get_nameservers(dns_ns_t *out, size_t cap, int *n);

size_t dns_cache_count(void);
int dns_cache_list(dns_cache_entry_t *out, size_t cap, size_t *n);
void dns_cache_flush(void);

size_t dns_log_count(void);
int dns_log_list(dns_req_log_t *out, size_t cap, size_t *n);
void dns_log_clear(void);

#endif
