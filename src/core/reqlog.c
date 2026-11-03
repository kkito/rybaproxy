#include "rybaproxy/reqlog.h"

#include <stdio.h>
#include <string.h>

/* geo 三态：1 / 0 / 未查(-1) */
static const char *tri(int v) {
    if (v > 0) return "1";
    if (v == 0) return "0";
    return "-";
}

static const char *or_dash(const char *s) { return (s && s[0]) ? s : "-"; }

/* snprintf 返回的是「本该写多长」，而调用方要的是 strlen：
 * 截断时返回 cap-1，未截断时返回真实长度。 */
static size_t finish_len(int n, size_t cap) {
    if (n < 0) return 0;
    return (size_t)n < cap ? (size_t)n : cap - 1;
}

size_t reqlog_format_route(char *out, size_t cap, const reqlog_route_t *r) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    if (!r) return 0;
    char rule[192];
    if (r->rule_id < 0) snprintf(rule, sizeof rule, "-/default");
    else snprintf(rule, sizeof rule, "%d/%s", r->rule_id, or_dash(r->rule_name));
    int n = snprintf(out, cap,
        "[%llu] 路由 host=%s:%u proto=%s method=%s client=%s rule=%s upstream=%s "
        "geo=site:%s,ip:%s,lan:%s",
        (unsigned long long)r->id, or_dash(r->host), (unsigned)r->port,
        or_dash(r->proto), or_dash(r->method), or_dash(r->client),
        rule, or_dash(r->upstream), tri(r->geo_site), tri(r->geo_host), tri(r->geo_lan));
    return finish_len(n, cap);
}

size_t reqlog_format_connect(char *out, size_t cap, uint64_t id, const char *upstream,
                             int ok, long ms, const char *err) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    int n;
    if (ok) {
        n = snprintf(out, cap, "[%llu] 连接 upstream=%s ok ms=%ld",
                     (unsigned long long)id, or_dash(upstream), ms);
    } else {
        n = snprintf(out, cap, "[%llu] 连接 upstream=%s fail ms=%ld err=%s",
                     (unsigned long long)id, or_dash(upstream), ms, or_dash(err));
    }
    return finish_len(n, cap);
}

size_t reqlog_format_finish(char *out, size_t cap, uint64_t id, const char *host, uint16_t port,
                            int status, long dur_ms, uint64_t up, uint64_t down, const char *err) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    char st[16];
    if (status <= 0) snprintf(st, sizeof st, "ok");
    else snprintf(st, sizeof st, "%d", status);
    int n;
    if (err && err[0]) {
        n = snprintf(out, cap,
            "[%llu] 结束 host=%s:%u status=%s dur=%ldms up=%llu down=%llu err=%s",
            (unsigned long long)id, or_dash(host), (unsigned)port, st, dur_ms,
            (unsigned long long)up, (unsigned long long)down, err);
    } else {
        n = snprintf(out, cap,
            "[%llu] 结束 host=%s:%u status=%s dur=%ldms up=%llu down=%llu",
            (unsigned long long)id, or_dash(host), (unsigned)port, st, dur_ms,
            (unsigned long long)up, (unsigned long long)down);
    }
    return finish_len(n, cap);
}
