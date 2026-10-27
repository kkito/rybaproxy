#include "rybaproxy/startup_info.h"

#include <stdio.h>
#include <string.h>

#include "rybaproxy/common.h"

/* 上游摘要：名字 + 地址；direct 无地址只显名字，禁用项标 (off) */
size_t upstream_summary(const upstream_profile_t *ups, int n, char *out, size_t outsz) {
    if (!out || outsz == 0) return 0;
    out[0] = '\0';
    if (!ups || n <= 0) {
        snprintf(out, outsz, "(none)");
        return strlen(out);
    }
    size_t used = 0;
    for (int i = 0; i < n; i++) {
        const upstream_profile_t *u = &ups[i];
        int w;
        if (u->type == UPSTREAM_DIRECT) {
            w = snprintf(out + used, outsz - used, "%s%s%s",
                         used ? ", " : "", u->name, u->enabled ? "" : " (off)");
        } else {
            w = snprintf(out + used, outsz - used, "%s%s %s://%s:%u%s",
                         used ? ", " : "", u->name,
                         u->type == UPSTREAM_HTTP ? "http" : "socks5",
                         u->host, (unsigned)u->port, u->enabled ? "" : " (off)");
        }
        if (w < 0 || (size_t)w >= outsz - used) {   /* 截断即止，不再拼下一项 */
            if ((size_t)w >= outsz - used) out[outsz - 1] = '\0';
            return strlen(out);
        }
        used += (size_t)w;
    }
    return used;
}

/* 启动信息：一屏说清"跑的是什么、连的什么、听在哪" */
size_t startup_info_text(const startup_info_t *i, char *out, size_t outsz) {
    if (!out || outsz == 0) return 0;
    if (!i) { out[0] = '\0'; return 0; }
    char geo[64];
    if (i->geo_ip_count < 0 || i->geo_site_count < 0)
        snprintf(geo, sizeof geo, "not loaded");
    else
        snprintf(geo, sizeof geo, "ip=%d site=%d (cache %d)",
                 i->geo_ip_count, i->geo_site_count, i->geo_cache_size);
    int n = snprintf(out, outsz,
        "rybaproxy %s (%s, built %s)%s\n"
        "  %-10s%s\n"
        "  %-10s%s\n"
        "  %-10s%s\n"
        "  %-10s%s (%s)\n"
        "  %-10s%s\n"
        "  %-10s%ld\n"
        "  %-10shttp %d | socks5 %d | web %d\n"
        "  %-10s%d (%s)\n"
        "  %-10s%d\n"
        "  %-10s%s\n",
        i->version, i->commit, i->build_time, i->detached ? " [detached]" : "",
        "config", i->config_path[0] ? i->config_path : "(defaults)",
        "data dir", i->data_dir,
        "database", i->db_path,
        "log", i->log_file, i->log_level,
        "pidfile", i->pid_file,
        "pid", i->pid,
        "listen", i->http_port, i->socks5_port, i->web_port,
        "upstreams", i->upstream_count, i->upstreams[0] ? i->upstreams : "(none)",
        "rules", i->rule_count,
        "geo", geo);
    if (n < 0) { out[0] = '\0'; return 0; }
    if ((size_t)n >= outsz) { out[outsz - 1] = '\0'; return outsz - 1; }
    return (size_t)n;
}
