#define _GNU_SOURCE
#include "rybaproxy/dns.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t g_dns_lock = PTHREAD_MUTEX_INITIALIZER;
static dns_resolver_fn g_resolver = NULL;
static int g_dns_timeout_sec = 5;

#define DNS_CACHE_CAP 1024
#define DNS_NEG_TTL_MIN 10
#define DNS_NEG_TTL_MAX 60
#define DNS_TTL_MIN 60
#define DNS_TTL_MAX 1800

typedef struct {
    char key[320];
    dns_cache_entry_t e;
    int used;
} dns_cache_ent_internal_t;

static dns_cache_ent_internal_t g_cache[DNS_CACHE_CAP];
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_dns_proxy[64] = "none";
static dns_ns_t g_nameservers[16];
static int g_ns_n = 0;

void dns_init(void) {}

void dns_set_resolver(dns_resolver_fn fn) {
    pthread_mutex_lock(&g_dns_lock);
    g_resolver = fn;
    pthread_mutex_unlock(&g_dns_lock);
}

void *dns_test_get_resolver(void) {
    pthread_mutex_lock(&g_dns_lock);
    void *r = (void *)g_resolver;
    pthread_mutex_unlock(&g_dns_lock);
    return r;
}

void dns_set_timeout_sec(int sec) {
    pthread_mutex_lock(&g_dns_lock);
    if (sec <= 0) sec = 5;
    g_dns_timeout_sec = sec;
    pthread_mutex_unlock(&g_dns_lock);
}

int dns_timeout_sec(void) {
    pthread_mutex_lock(&g_dns_lock);
    int t = g_dns_timeout_sec;
    pthread_mutex_unlock(&g_dns_lock);
    return t;
}

static int sys_resolve_first(const char *host, const char *serv,
                             char *ip_out, size_t ipsz) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    const char *s = (serv && *serv) ? serv : "0";
    if (getaddrinfo(host, s, &hints, &res) != 0 || !res) return -1;
    void *ap = NULL;
    if (res->ai_family == AF_INET)
        ap = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
    else if (res->ai_family == AF_INET6)
        ap = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
    int rc = -1;
    if (ap && inet_ntop(res->ai_family, ap, ip_out, (socklen_t)ipsz)) rc = 0;
    freeaddrinfo(res);
    return rc;
}

int dns_resolve_first(const char *host, const char *serv,
                      char *ip_out, size_t ipsz) {
    if (!host || !*host || !ip_out || ipsz == 0) return -1;
    ip_out[0] = '\0';
    pthread_mutex_lock(&g_dns_lock);
    dns_resolver_fn fn = g_resolver;
    pthread_mutex_unlock(&g_dns_lock);
    if (fn) return fn(host, ip_out, ipsz);
    return sys_resolve_first(host, serv, ip_out, ipsz);
}

int dns_getaddrinfo(const char *host, const char *serv,
                    const struct addrinfo *hints, struct addrinfo **res) {
    if (!res) return EAI_BADFLAGS;
    *res = NULL;
    pthread_mutex_lock(&g_dns_lock);
    dns_resolver_fn fn = g_resolver;
    pthread_mutex_unlock(&g_dns_lock);
    if (fn) {
        /* 测试注入时：只返回首个解析结果的单节点链，保留调用方的遍历语义。 */
        char ip_out[64] = "";
        if (fn(host, ip_out, sizeof ip_out) != 0 || !ip_out[0]) return EAI_FAIL;
        struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
        if (!ai) return EAI_MEMORY;
        struct sockaddr_storage *ss = calloc(1, sizeof(struct sockaddr_storage));
        if (!ss) { free(ai); return EAI_MEMORY; }
        int port = 0;
        if (serv && *serv) port = atoi(serv);
        if (inet_pton(AF_INET, ip_out, &((struct sockaddr_in *)ss)->sin_addr) == 1) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ss;
            sin->sin_family = AF_INET;
            sin->sin_port = htons((uint16_t)port);
            ai->ai_family = AF_INET;
            ai->ai_addrlen = sizeof(struct sockaddr_in);
            ai->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
            ai->ai_protocol = hints ? hints->ai_protocol : 0;
            ai->ai_addr = (struct sockaddr *)sin;
        } else if (inet_pton(AF_INET6, ip_out, &((struct sockaddr_in6 *)ss)->sin6_addr) == 1) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons((uint16_t)port);
            ai->ai_family = AF_INET6;
            ai->ai_addrlen = sizeof(struct sockaddr_in6);
            ai->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
            ai->ai_protocol = hints ? hints->ai_protocol : 0;
            ai->ai_addr = (struct sockaddr *)sin6;
        } else {
            free(ss); free(ai); return EAI_FAIL;
        }
        *res = ai;
        return 0;
    }
    struct addrinfo h = {0};
    if (hints) h = *hints;
    if (h.ai_family == 0) h.ai_family = AF_UNSPEC;
    if (h.ai_socktype == 0) h.ai_socktype = SOCK_STREAM;
    const char *s = (serv && *serv) ? serv : "0";
    return getaddrinfo(host, s, &h, res);
}

/* 增强版本接口（案） */
static int dns_clamp_ttl(int ttl, int is_neg) {
    if (is_neg) {
        if (ttl < DNS_NEG_TTL_MIN) ttl = DNS_NEG_TTL_MIN;
        if (ttl > DNS_NEG_TTL_MAX) ttl = DNS_NEG_TTL_MAX;
        return ttl;
    }
    if (ttl < DNS_TTL_MIN) ttl = DNS_TTL_MIN;
    if (ttl > DNS_TTL_MAX) ttl = DNS_TTL_MAX;
    return ttl;
}

static void dns_make_pos_key(const char *domain, dns_class_t cls, char *out, size_t outsz) {
    snprintf(out, outsz, "dns:v1:%d:%s", (int)cls, domain ? domain : "");
}

static void dns_make_neg_key(const char *domain, dns_class_t cls, const char *resolver_id, char *out, size_t outsz) {
    snprintf(out, outsz, "dns:v1:%d:%s:%s:neg", (int)cls, domain ? domain : "", resolver_id ? resolver_id : "");
}

int dns_resolve(const char *domain, dns_class_t cls, dns_result_t *out) {
    if (!domain || !out) return -1;
    pthread_mutex_lock(&g_cache_lock);
    char key[320];
    dns_make_pos_key(domain, cls, key, sizeof key);
    time_t now = time(NULL);
    for (int i = 0; i < DNS_CACHE_CAP; i++) {
        if (g_cache[i].used && strcmp(g_cache[i].key, key) == 0 && !g_cache[i].e.negative) {
            if (g_cache[i].e.expire_at > now) {
                out->ip_n = g_cache[i].e.ip_n;
                for (int j = 0; j < out->ip_n && j < 4; j++) snprintf(out->ips[j], sizeof out->ips[j], "%s", g_cache[i].e.ips[j]);
                out->ttl = g_cache[i].e.ttl_eff;
                out->class = g_cache[i].e.class;
                snprintf(out->resolver_id, sizeof out->resolver_id, "%s", g_cache[i].e.resolver_id);
                out->from_cache = true;
                g_cache[i].e.last_used = now;
                g_cache[i].e.hits++;
                pthread_mutex_unlock(&g_cache_lock);
                return 0;
            }
        }
    }
    pthread_mutex_unlock(&g_cache_lock);
    return -1;
}

int dns_set_proxy(const char *spec) {
    pthread_mutex_lock(&g_dns_lock);
    if (spec && *spec) snprintf(g_dns_proxy, sizeof g_dns_proxy, "%s", spec);
    else snprintf(g_dns_proxy, sizeof g_dns_proxy, "none");
    pthread_mutex_unlock(&g_dns_lock);
    return 0;
}

const char *dns_get_proxy(void) {
    return g_dns_proxy;
}

int dns_set_nameservers(const dns_ns_t *list, size_t n) {
    pthread_mutex_lock(&g_dns_lock);
    g_ns_n = 0;
    if (list && n > 0) {
        size_t m = n > (size_t)(sizeof g_nameservers)/sizeof g_nameservers[0] ? (sizeof g_nameservers)/sizeof g_nameservers[0] : n;
        for (size_t i = 0; i < m; i++) g_nameservers[g_ns_n++] = list[i];
    }
    pthread_mutex_unlock(&g_dns_lock);
    return 0;
}

int dns_add_nameserver(const dns_ns_t *ns) {
    if (!ns) return -1;
    pthread_mutex_lock(&g_dns_lock);
    if (g_ns_n < (int)(sizeof g_nameservers)/sizeof g_nameservers[0]) {
        g_nameservers[g_ns_n++] = *ns;
        pthread_mutex_unlock(&g_dns_lock);
        return 0;
    }
    pthread_mutex_unlock(&g_dns_lock);
    return -1;
}

int dns_clear_nameservers(void) {
    pthread_mutex_lock(&g_dns_lock);
    g_ns_n = 0;
    pthread_mutex_unlock(&g_dns_lock);
    return 0;
}

int dns_get_nameservers(dns_ns_t *out, size_t cap, int *n) {
    if (n) *n = 0;
    if (!out || cap == 0) return 0;
    pthread_mutex_lock(&g_dns_lock);
    int c = 0;
    for (int i = 0; i < g_ns_n && c < (int)cap; i++) {
        out[c++] = g_nameservers[i];
    }
    pthread_mutex_unlock(&g_dns_lock);
    if (n) *n = c;
    return 0;
}

size_t dns_cache_count(void) {
    pthread_mutex_lock(&g_cache_lock);
    size_t c = 0;
    time_t now = time(NULL);
    for (int i = 0; i < DNS_CACHE_CAP; i++) if (g_cache[i].used && g_cache[i].e.expire_at > now) c++;
    pthread_mutex_unlock(&g_cache_lock);
    return c;
}

int dns_cache_list(dns_cache_entry_t *out, size_t cap, size_t *n) {
    if (n) *n = 0;
    if (!out || cap == 0) return 0;
    pthread_mutex_lock(&g_cache_lock);
    size_t c = 0;
    time_t now = time(NULL);
    for (int i = 0; i < DNS_CACHE_CAP && c < cap; i++) {
        if (!g_cache[i].used) continue;
        if (g_cache[i].e.expire_at <= now) continue;
        out[c++] = g_cache[i].e;
    }
    pthread_mutex_unlock(&g_cache_lock);
    if (n) *n = c;
    return 0;
}

void dns_cache_flush(void) {
    pthread_mutex_lock(&g_cache_lock);
    memset(g_cache, 0, sizeof g_cache);
    pthread_mutex_unlock(&g_cache_lock);
}

size_t dns_log_count(void) { return 0; }
int dns_log_list(dns_req_log_t *out, size_t cap, size_t *n) { if (n) *n = 0; (void)out; (void)cap; return 0; }
void dns_log_clear(void) {}
