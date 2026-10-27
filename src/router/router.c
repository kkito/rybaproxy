#include "rybaproxy/router.h"
#include "rybaproxy/geo.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void router_init(router_t *r, const char *def, bool fallback) {
    memset(r, 0, sizeof *r);
    if (def) snprintf(r->default_upstream, sizeof r->default_upstream, "%s", def);
    else strcpy(r->default_upstream, "direct");
    r->fallback_to_direct = fallback;
    r->next_rule_id = 1;
}

void router_free(router_t *r) {
    free(r->rules);
    r->rules = NULL;
    r->count = r->cap = 0;
}

int router_add_rule(router_t *r, const rule_t *rule) {
    if (r->count == r->cap) {
        int ncap = r->cap ? r->cap * 2 : 16;
        rule_t *nr = realloc(r->rules, ncap * sizeof *nr);
        if (!nr) return -1;
        r->rules = nr;
        r->cap = ncap;
    }
    r->rules[r->count++] = *rule;
    return 0;
}

int router_remove_rule(router_t *r, int id) {
    for (int i = 0; i < r->count; i++) {
        if (r->rules[i].id == id) {
            memmove(&r->rules[i], &r->rules[i+1], (r->count-i-1)*sizeof(rule_t));
            r->count--;
            return 0;
        }
    }
    return -1;
}

static int rule_matches(const rule_t *rule, const char *host, int port, protocol_t proto, const char *client_ip) {
    if (!rule->enabled) return 0;
    if (rule->port != 0 && rule->port != port) return 0;
    if (rule->protocol != 0 && rule->protocol != proto) return 0;
    if (rule->domain_pattern[0]) {
        if (!match_domain(rule->domain_pattern, host)) return 0;
    }
    if (rule->ip_cidr[0]) {
        if (!match_cidr(rule->ip_cidr, client_ip ? client_ip : "")) return 0;
        /* if domain rule also has cidr, require both; ip-only rules should leave domain empty */
    }
    if (rule->geo_ip[0]) {
        int cn = geo_host_is_cn(host);
        if (strcmp(rule->geo_ip, "cn") == 0 && cn != 1) return 0;
        else if (strcmp(rule->geo_ip, "!cn") == 0 && cn == 1) return 0;
        else if (rule->geo_ip[0] && strcmp(rule->geo_ip, "cn") != 0 && strcmp(rule->geo_ip, "!cn") != 0) return 0;
    }
    if (rule->geo_site[0]) {
        int cn = geo_site_is_cn(host);
        if (strcmp(rule->geo_site, "cn") == 0 && cn != 1) return 0;
        else if (strcmp(rule->geo_site, "!cn") == 0 && cn == 1) return 0;
        else if (rule->geo_site[0] && strcmp(rule->geo_site, "cn") != 0 && strcmp(rule->geo_site, "!cn") != 0) return 0;
    }
    return 1;
}

int router_select(const router_t *r, const char *host, int port, protocol_t proto, const char *client_ip) {
    int best_idx = -1;
    int best_prio = -1;
    for (int i = 0; i < r->count; i++) {
        const rule_t *rule = &r->rules[i];
        if (!rule_matches(rule, host, port, proto, client_ip)) continue;
        if (rule->priority > best_prio || (rule->priority == best_prio && (best_idx == -1 || rule->id < r->rules[best_idx].id))) {
            best_prio = rule->priority;
            best_idx = i;
        }
    }
    if (best_idx >= 0) return r->rules[best_idx].upstream_id;
    return -1; /* caller uses default */
}

/* domain matching */
int match_domain(const char *pattern, const char *host) {
    if (!pattern || !host) return 0;
    if (strcmp(pattern, "*") == 0) return 1;
    /* lowercase copies */
    char p[RYBA_PATTERN_MAX], h[RYBA_PATTERN_MAX];
    snprintf(p, sizeof p, "%s", pattern);
    snprintf(h, sizeof h, "%s", host);
    for (char *c = p; *c; c++) *c = (char)tolower((unsigned char)*c);
    for (char *c = h; *c; c++) *c = (char)tolower((unsigned char)*c);
    /* strip trailing dot */
    size_t lp = strlen(p); if (lp && p[lp-1]=='.') p[lp-1]='\0';
    size_t lh = strlen(h); if (lh && h[lh-1]=='.') h[lh-1]='\0';

    if (p[0] == '.') {
        /* .example.com matches example.com and subdomains */
        if (strcmp(h, p+1) == 0) return 1;
        size_t plen = strlen(p+1);
        size_t hlen = strlen(h);
        if (hlen > plen && h[hlen-plen-1] == '.' && strcmp(h + (hlen-plen), p+1) == 0) return 1;
        return 0;
    }
    if (p[0] == '*' && p[1] == '.') {
        /* *.example.com matches a single leading label */
        const char *suffix = p + 2; /* example.com */
        size_t slen = strlen(suffix);
        size_t hlen = strlen(h);
        if (hlen <= slen + 1) return 0;
        /* host must end with .suffix */
        if (h[hlen - slen - 1] != '.') return 0;
        if (strcmp(h + (hlen - slen), suffix) != 0) return 0;
        /* prefix label must be non-empty and contain no dot */
        size_t prefix_len = hlen - slen - 1;
        for (size_t i = 0; i < prefix_len; i++) if (h[i] == '.') return 0;
        return prefix_len > 0 ? 1 : 0;
    }
    return strcmp(p, h) == 0;
}

/* IPv4 CIDR */
static int parse_ipv4(const char *s, unsigned int *out) {
    unsigned int a,b,c,d;
    if (sscanf(s, "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return -1;
    if (a>255||b>255||c>255||d>255) return -1;
    *out = (a<<24)|(b<<16)|(c<<8)|d;
    return 0;
}

int match_cidr(const char *cidr, const char *ip) {
    if (!cidr || !cidr[0]) return 1; /* no constraint */
    if (!ip || !ip[0]) return 0;
    char buf[64];
    snprintf(buf, sizeof buf, "%s", cidr);
    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) { *slash = '\0'; prefix = atoi(slash+1); }
    unsigned int net, hostip;
    if (parse_ipv4(buf, &net) != 0) return 0;
    if (parse_ipv4(ip, &hostip) != 0) return 0;
    if (prefix < 0 || prefix > 32) return 0;
    unsigned int mask = prefix == 0 ? 0 : (~0u << (32-prefix));
    return (net & mask) == (hostip & mask);
}
