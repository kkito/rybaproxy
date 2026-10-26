#include "rybaproxy/config.h"
#include "rybaproxy/upstream.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void copy_str(char *dst, size_t dstsz, const cJSON *obj, const char *key) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsString(v) && v->valuestring) {
        snprintf(dst, dstsz, "%s", v->valuestring);
    }
}

static int get_int(const cJSON *obj, const char *key, int fallback) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsNumber(v)) return v->valueint;
    return fallback;
}

static bool get_bool(const cJSON *obj, const char *key, bool fallback) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsBool(v)) return cJSON_IsTrue(v);
    return fallback;
}

void config_init_defaults(config_t *c) {
    memset(c, 0, sizeof *c);
    c->http_port = 8080;
    c->socks5_port = 1080;
    c->max_connections = 10240;
    c->idle_timeout_sec = 300;
    c->max_session_sec = 3600;
    c->connect_timeout_sec = 10;
    c->dns_timeout_sec = 5;
    c->fallback_to_direct = true;
    c->resolve_for_routing = false;
    strcpy(c->default_upstream, "direct");
    strcpy(c->db_path, "/var/lib/rybaproxy/stats.db");
    c->retention_days = 90;
}

int config_load(const char *path, config_t *c) {
    config_init_defaults(c);
    if (!path || !path[0]) return 0;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return -1; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) return -1;

    const cJSON *proxy = cJSON_GetObjectItemCaseSensitive(root, "proxy");
    if (cJSON_IsObject(proxy)) {
        c->http_port = get_int(proxy, "http_port", c->http_port);
        /* support http_listen? keep simple: ports only in v1 */
        c->socks5_port = get_int(proxy, "socks5_port", c->socks5_port);
        c->proxy_auth_enabled = get_bool(proxy, "proxy_auth_enabled", c->proxy_auth_enabled);
        copy_str(c->proxy_username, sizeof c->proxy_username, proxy, "proxy_username");
        copy_str(c->proxy_password, sizeof c->proxy_password, proxy, "proxy_password");
    }
    /* allow top-level port overrides too */
    c->http_port = get_int(root, "http_port", c->http_port);
    c->socks5_port = get_int(root, "socks5_port", c->socks5_port);

    const cJSON *limits = cJSON_GetObjectItemCaseSensitive(root, "limits");
    if (cJSON_IsObject(limits)) {
        c->max_connections = get_int(limits, "max_connections", c->max_connections);
        c->idle_timeout_sec = get_int(limits, "idle_timeout_sec", c->idle_timeout_sec);
        c->max_session_sec = get_int(limits, "max_session_sec", c->max_session_sec);
        c->connect_timeout_sec = get_int(limits, "connect_timeout_sec", c->connect_timeout_sec);
        c->dns_timeout_sec = get_int(limits, "dns_timeout_sec", c->dns_timeout_sec);
    }

    const cJSON *routing = cJSON_GetObjectItemCaseSensitive(root, "routing");
    if (cJSON_IsObject(routing)) {
        copy_str(c->default_upstream, sizeof c->default_upstream, routing, "default_upstream");
        c->fallback_to_direct = get_bool(routing, "fallback_to_direct", c->fallback_to_direct);
        c->resolve_for_routing = get_bool(routing, "resolve_for_routing", c->resolve_for_routing);
    }

    const cJSON *stats = cJSON_GetObjectItemCaseSensitive(root, "stats");
    if (cJSON_IsObject(stats)) {
        copy_str(c->db_path, sizeof c->db_path, stats, "db_path");
        c->retention_days = get_int(stats, "retention_days", c->retention_days);
    }

    const cJSON *ups = cJSON_GetObjectItemCaseSensitive(root, "upstreams");
    if (cJSON_IsArray(ups)) {
        int n = cJSON_GetArraySize(ups);
        c->upstreams = calloc((size_t)n, sizeof(upstream_profile_t));
        c->upstream_count = n;
        for (int i = 0; i < n; i++) {
            const cJSON *u = cJSON_GetArrayItem(ups, i);
            upstream_profile_t *p = &c->upstreams[i];
            p->id = i;
            p->enabled = 1;
            copy_str(p->name, sizeof p->name, u, "name");
            char type[32]; type[0]='\0';
            const cJSON *t = cJSON_GetObjectItemCaseSensitive(u, "type");
            if (cJSON_IsString(t)) snprintf(type, sizeof type, "%s", t->valuestring);
            if (strcmp(type, "http") == 0) p->type = UPSTREAM_HTTP;
            else if (strcmp(type, "socks5") == 0) p->type = UPSTREAM_SOCKS5;
            else p->type = UPSTREAM_DIRECT;
            copy_str(p->host, sizeof p->host, u, "host");
            p->port = (uint16_t)get_int(u, "port", p->port);
            copy_str(p->username, sizeof p->username, u, "username");
            copy_str(p->password, sizeof p->password, u, "password");
            const cJSON *en = cJSON_GetObjectItemCaseSensitive(u, "enabled");
            if (cJSON_IsBool(en)) p->enabled = cJSON_IsTrue(en);
        }
    }

    cJSON_Delete(root);
    return 0;
}

void config_free(config_t *c) { if (c) free(c->upstreams); c->upstreams=NULL; c->upstream_count=0; }
