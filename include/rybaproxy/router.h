#ifndef RYBAPROXY_ROUTER_H
#define RYBAPROXY_ROUTER_H

#include "rybaproxy/common.h"
#include "rybaproxy/config.h"

#define RYBA_RULE_NAME_MAX 64
#define RYBA_PATTERN_MAX 256

typedef struct {
    int id;
    int priority;
    int enabled;
    char name[RYBA_RULE_NAME_MAX];
    char domain_pattern[RYBA_PATTERN_MAX];
    char ip_cidr[64];
    int port;          /* 0 = any */
    protocol_t protocol; /* 0 = any */
    int upstream_id;
} rule_t;

typedef struct {
    rule_t *rules;
    int count;
    int cap;
    int next_rule_id;
    char default_upstream[RYBA_NAME_MAX];
    bool fallback_to_direct;
} router_t;

void router_init(router_t *r, const char *default_upstream, bool fallback);
void router_free(router_t *r);
int router_add_rule(router_t *r, const rule_t *rule);
int router_remove_rule(router_t *r, int id);
int router_select(const router_t *r, const char *host, int port, protocol_t proto, const char *client_ip);
/* helpers exposed for tests */
int match_domain(const char *pattern, const char *host);
int match_cidr(const char *cidr, const char *ip);
#endif
