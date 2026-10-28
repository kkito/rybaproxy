#include "rybaproxy/web_api.h"
#include "rybaproxy/stats.h"
#include "rybaproxy/db.h"
#include "rybaproxy/router.h"
#include "rybaproxy/upstream.h"
#include "rybaproxy/dns.h"

#include "rybaproxy/geo.h"

#include <arpa/inet.h>
#include <civetweb.h>
#include <cjson/cJSON.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* 版本号由构建期生成的 version.h 注入（git describe / VERSION 文件） */
#include "rybaproxy/log.h"
#include "rybaproxy/version.h"

char *web_envelope_json(const char *data_json, const char *err_code, const char *err_msg) {
    if (err_code) {
        char *s = malloc(256 + (err_msg ? strlen(err_msg) : 0));
        if (!s) return NULL;
        snprintf(s, 256 + (err_msg ? strlen(err_msg) : 0),
            "{\"ok\":false,\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}",
            err_code, err_msg ? err_msg : "");
        return s;
    }
    size_t dl = data_json ? strlen(data_json) : 4;
    char *s = malloc(dl + 32);
    if (!s) return NULL;
    snprintf(s, dl + 32, "{\"ok\":true,\"data\":%s}", data_json ? data_json : "null");
    return s;
}

char *web_envelope_paged(const char *inner_paged_json) {
    /* inner: {"data":[...],"total":N,"limit":L,"offset":O} -> {"ok":true,"data":[...],"total":N,"limit":L,"offset":O} */
    if (!inner_paged_json) return web_envelope_json("[]", NULL, NULL);
    const char *p = strstr(inner_paged_json, "\"data\"");
    if (!p) return web_envelope_json("[]", NULL, NULL);
    /* find the value after "data": */
    const char *colon = strchr(p + 6, ':');
    if (!colon) return web_envelope_json("[]", NULL, NULL);
    /* split total/limit/offset: parse with sscanf on the whole string */
    int total = 0, limit = 0, offset = 0;
    const char *pt = strstr(inner_paged_json, "\"total\":");
    const char *pl = strstr(inner_paged_json, "\"limit\":");
    const char *po = strstr(inner_paged_json, "\"offset\":");
    if (pt) total = atoi(pt + 8);
    if (pl) limit = atoi(pl + 8);
    if (po) offset = atoi(po + 9);
    /* extract data array substring */
    const char *arr = colon + 1;
    while (*arr == ' ' || *arr == '\t') arr++;
    /* find matching close: inner ends with ],"total"... so locate ,"total" */
    const char *tend = strstr(inner_paged_json, ",\"total\"");
    size_t arrlen = tend ? (size_t)(tend - arr) : strlen(arr);
    size_t need = arrlen + 128;
    char *s = malloc(need);
    if (!s) return NULL;
    snprintf(s, need, "{\"ok\":true,\"data\":%.*s,\"total\":%d,\"limit\":%d,\"offset\":%d}",
        (int)arrlen, arr, total, limit, offset);
    return s;
}

static void sql_escape(const char *src, char *dst, size_t dstsz) {
    size_t k = 0;
    for (size_t i = 0; src && src[i] && k + 2 < dstsz; i++) {
        if (src[i] == '\'') dst[k++] = '\'';
        dst[k++] = src[i];
    }
    dst[k] = '\0';
}

int web_rules_db_save(const rule_t *r) {
    if (!r) return -1;
    char pat[512], cidr[128], gip[32], gsite[32], nm[128];
    sql_escape(r->domain_pattern, pat, sizeof pat);
    sql_escape(r->ip_cidr, cidr, sizeof cidr);
    sql_escape(r->geo_ip, gip, sizeof gip);
    sql_escape(r->geo_site, gsite, sizeof gsite);
    sql_escape(r->name, nm, sizeof nm);
    const char *ps = "any";
    if (r->protocol == PROTO_HTTP) ps = "http";
    else if (r->protocol == PROTO_SOCKS5) ps = "socks5";
    char sql[2048];
    snprintf(sql, sizeof sql,
        "INSERT INTO rules(id,name,priority,enabled,domain_pattern,geo_ip,geo_site,ip_cidr,port,protocol,upstream_id,created_at,updated_at) "
        "VALUES(%d,'%s',%d,%d,'%s','%s','%s','%s',%d,'%s',%d,strftime('%%s','now'),strftime('%%s','now')) "
        "ON CONFLICT(id) DO UPDATE SET name='%s',priority=%d,enabled=%d,domain_pattern='%s',geo_ip='%s',geo_site='%s',ip_cidr='%s',port=%d,protocol='%s',upstream_id=%d,updated_at=strftime('%%s','now');",
        r->id, nm, r->priority, r->enabled, pat, gip, gsite, cidr, r->port, ps, r->upstream_id,
        nm, r->priority, r->enabled, pat, gip, gsite, cidr, r->port, ps, r->upstream_id);
    return db_exec_raw(sql);
}

int web_rules_db_delete(int id) {
    char sql[128];
    snprintf(sql, sizeof sql, "DELETE FROM rules WHERE id=%d;", id);
    return db_exec_raw(sql);
}

int web_rules_db_load_all(router_t *r) {
    if (!r) return -1;
    return db_rules_load(r);
}

int web_rules_reload(router_t *r) {
    if (!r) return -1;
    for (int i = 0; i < r->count; i++)
        for (int j = i + 1; j < r->count; j++)
            if (r->rules[j].priority < r->rules[i].priority) {
                rule_t t = r->rules[i]; r->rules[i] = r->rules[j]; r->rules[j] = t;
            }
    return 0;
}

static const char *upstream_type_str(int t) {
    if (t == UPSTREAM_HTTP) return "http";
    if (t == UPSTREAM_SOCKS5) return "socks5";
    return "direct";
}

static int upstream_type_from_str(const char *s) {
    if (!s) return UPSTREAM_DIRECT;
    if (strcmp(s, "http") == 0) return UPSTREAM_HTTP;
    if (strcmp(s, "socks5") == 0 || strcmp(s, "socks") == 0) return UPSTREAM_SOCKS5;
    return UPSTREAM_DIRECT;
}

int web_upstreams_update(server_ctx_t *srv, int id, const char *body, char **out_envelope, int *out_status) {
    if (out_status) *out_status = 200;
    if (out_envelope) *out_envelope = NULL;
    cJSON *j = cJSON_Parse(body ? body : "{}");
    if (!j) {
        if (out_envelope) *out_envelope = web_envelope_json(NULL, "BAD_JSON", "bad json");
        if (out_status) *out_status = 400;
        return 0;
    }
    pthread_mutex_lock(&srv->lock);
    upstream_profile_t *u = NULL;
    for (int i = 0; i < srv->upstream_count; i++)
        if (srv->upstreams[i].id == id) { u = &srv->upstreams[i]; break; }
    if (!u) {
        pthread_mutex_unlock(&srv->lock);
        cJSON_Delete(j);
        if (out_envelope) *out_envelope = web_envelope_json(NULL, "NOT_FOUND", "upstream not found");
        if (out_status) *out_status = 404;
        return 0;
    }
    cJSON *v;
    if ((v = cJSON_GetObjectItem(j, "name")) && cJSON_IsString(v))
        snprintf(u->name, sizeof u->name, "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(j, "type")) && cJSON_IsString(v))
        u->type = upstream_type_from_str(v->valuestring);
    if ((v = cJSON_GetObjectItem(j, "host")) && cJSON_IsString(v))
        snprintf(u->host, sizeof u->host, "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(j, "port"))) u->port = (uint16_t)v->valueint;
    if ((v = cJSON_GetObjectItem(j, "username")) && cJSON_IsString(v))
        snprintf(u->username, sizeof u->username, "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(j, "password")) && cJSON_IsString(v))
        snprintf(u->password, sizeof u->password, "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(j, "enabled"))) u->enabled = cJSON_IsTrue(v) ? 1 : 0;
    int uid = u->id;
    char sql_esc_name[RYBA_NAME_MAX * 2 + 1], sql_esc_host[512 + 1];
    char sql_esc_user[128 * 2 + 1], sql_esc_pass[128 * 2 + 1];
    /* minimal ' escape for SQL */
    size_t k = 0;
    for (size_t i = 0; u->name[i] && k + 2 < sizeof sql_esc_name; i++) {
        if (u->name[i] == '\'') sql_esc_name[k++] = '\'';
        sql_esc_name[k++] = u->name[i];
    }
    sql_esc_name[k] = '\0';
    k = 0;
    for (size_t i = 0; u->host[i] && k + 2 < sizeof sql_esc_host; i++) {
        if (u->host[i] == '\'') sql_esc_host[k++] = '\'';
        sql_esc_host[k++] = u->host[i];
    }
    sql_esc_host[k] = '\0';
    k = 0;
    for (size_t i = 0; u->username[i] && k + 2 < sizeof sql_esc_user; i++) {
        if (u->username[i] == '\'') sql_esc_user[k++] = '\'';
        sql_esc_user[k++] = u->username[i];
    }
    sql_esc_user[k] = '\0';
    k = 0;
    for (size_t i = 0; u->password[i] && k + 2 < sizeof sql_esc_pass; i++) {
        if (u->password[i] == '\'') sql_esc_pass[k++] = '\'';
        sql_esc_pass[k++] = u->password[i];
    }
    sql_esc_pass[k] = '\0';
    char sql[2200];
    const char *tstr = upstream_type_str(u->type);
    snprintf(sql, sizeof sql,
        "INSERT INTO upstream_profiles(id,name,type,host,port,username,password,enabled,created_at,updated_at) "
        "VALUES(%d,'%s','%s','%s',%d,'%s','%s',%d,strftime('%%s','now'),strftime('%%s','now')) "
        "ON CONFLICT(id) DO UPDATE SET name='%s',type='%s',host='%s',port=%d,username='%s',password='%s',enabled=%d,updated_at=strftime('%%s','now');",
        uid, sql_esc_name, tstr, sql_esc_host, u->port, sql_esc_user, sql_esc_pass, u->enabled,
        sql_esc_name, tstr, sql_esc_host, u->port, sql_esc_user, sql_esc_pass, u->enabled);
    pthread_mutex_unlock(&srv->lock);
    cJSON_Delete(j);
    /* NOTE: db persistence for upstreams requires a db handle API; memory update done above.
       SQL string executed via db_exec helper below (best effort, ignored when db closed). */
    extern int db_exec_raw(const char *sql);
    db_exec_raw(sql);
    if (out_envelope) *out_envelope = web_envelope_json("{\"ok\":true}", NULL, NULL);
    return 0;
}

/* ---------- ring log ---------- */
#define WEB_LOG_CAP 512
#define WEB_LOG_MSGSZ 256
static char g_logs[WEB_LOG_CAP][WEB_LOG_MSGSZ];
static char g_log_levels[WEB_LOG_CAP][16];
static long long g_log_ts[WEB_LOG_CAP];
static int g_log_head = 0, g_log_count = 0;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

void web_log_push(const char *level, const char *msg) {
    pthread_mutex_lock(&g_log_lock);
    int i = (g_log_head + g_log_count) % WEB_LOG_CAP;
    if (g_log_count == WEB_LOG_CAP) { g_log_head = (g_log_head + 1) % WEB_LOG_CAP; i = (g_log_head + g_log_count - 1) % WEB_LOG_CAP; }
    else g_log_count++;
    snprintf(g_log_levels[i], sizeof g_log_levels[i], "%s", level ? level : "INFO");
    snprintf(g_logs[i], sizeof g_logs[i], "%s", msg ? msg : "");
    g_log_ts[i] = (long long)time(NULL) * 1000LL;
    pthread_mutex_unlock(&g_log_lock);
}

int web_log_query(const char *level, int limit, char *buf, size_t bufsz) {
    if (!buf || bufsz == 0) return -1;
    if (limit <= 0) limit = 100;
    if (limit > WEB_LOG_CAP) limit = WEB_LOG_CAP;
    size_t pos = 0;
    pos += snprintf(buf + pos, bufsz - pos, "[");
    pthread_mutex_lock(&g_log_lock);
    int shown = 0, first = 1;
    for (int k = g_log_count - 1; k >= 0 && shown < limit; k--) {
        int i = (g_log_head + k) % WEB_LOG_CAP;
        if (level && level[0] && strcmp(level, g_log_levels[i]) != 0) continue;
        char item[WEB_LOG_MSGSZ + 64];
        snprintf(item, sizeof item, "%s{\"level\":\"%s\",\"msg\":\"%s\",\"ts\":%lld}",
            first ? "" : ",", g_log_levels[i], g_logs[i], g_log_ts[i]);
        first = 0; shown++;
        size_t il = strlen(item);
        if (pos + il + 2 >= bufsz) break;
        memcpy(buf + pos, item, il);
        pos += il;
    }
    pthread_mutex_unlock(&g_log_lock);
    snprintf(buf + pos, bufsz - pos, "]");
    return 0;
}

/* ---------- HTTP plumbing ---------- */
static void send_json(struct mg_connection *conn, int status, const char *body) {
    mg_printf(conn, "HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
              status, (int)strlen(body));
    mg_write(conn, body, strlen(body));
}

int valid_geo(const char *s) {
    return !s || !*s || strcmp(s, "cn") == 0 || strcmp(s, "!cn") == 0
        || strcmp(s, "lan") == 0 || strcmp(s, "!lan") == 0;
}

static void send_envelope(struct mg_connection *conn, int status, char *env) {
    if (!env) { send_json(conn, 500, "{\"ok\":false,\"error\":{\"code\":\"INTERNAL\",\"message\":\"alloc\"}}"); return; }
    send_json(conn, status, env);
    free(env);
}

static int parse_id(const char *uri, const char *prefix, const char *query) {
    /* /api/xxx/<id> or ?id= */
    size_t pl = strlen(prefix);
    if (strncmp(uri, prefix, pl) == 0 && uri[pl] == '/') return atoi(uri + pl + 1);
    if (query && query[0]) {
        char val[32]; val[0] = '\0';
        mg_get_var(query, strlen(query), "id", val, sizeof val);
        if (val[0]) return atoi(val);
    }
    return -1;
}

static long long qnum(const char *query, const char *name) {
    if (!query || !query[0]) return 0;
    char val[64]; val[0] = '\0';
    mg_get_var(query, strlen(query), name, val, sizeof val);
    return val[0] ? atoll(val) : 0;
}

static void qstr(const char *query, const char *name, char *out, size_t outsz) {
    out[0] = '\0';
    if (!query || !query[0]) return;
    mg_get_var(query, strlen(query), name, out, outsz);
}

static void read_body(struct mg_connection *conn, char *buf, size_t bufsz) {
    const struct mg_request_info *ri = mg_get_request_info(conn);
    long long want = ri ? ri->content_length : 0;
    size_t got = 0;
    buf[0] = '\0';
    if (want <= 0) return;
    if (want > (long long)(bufsz - 1)) return; /* too large: treat as empty -> BAD_JSON */
    while (got < (size_t)want) {
        int n = mg_read(conn, buf + got, (size_t)want - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    buf[got] = '\0';
}

/* 64K 响应缓冲放堆：civetweb 工作线程栈仅 ~144KB（crash 日志实测），栈上直接爆栈 */
#define W_AUTO_FREE __attribute__((cleanup(w_auto_free)))
static void w_auto_free(void *p) { void *q = *(void **)p; if (q) free(q); }

void web_api_dispatch(struct mg_connection *conn, server_ctx_t *srv, const char *uri, const char *method, const char *query) {
    LOG_DEBUG("web %s %s", method, uri);
    char *body W_AUTO_FREE = malloc(4096);
    char *tmp W_AUTO_FREE = malloc(65536);
    size_t tmpsz = 65536;
    if (!body || !tmp) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }

    if (strcmp(uri, "/healthz") == 0) {
        char d[128];
        snprintf(d, sizeof d, "{\"status\":\"ok\",\"version\":\"%s\"}", RYBA_VERSION);
        send_envelope(conn, 200, web_envelope_json(d, NULL, NULL));
        return;
    }
    if (strcmp(uri, "/api/metrics") == 0 || strcmp(uri, "/api/stats") == 0) {
        stats_snapshot_t snap = stats_get();
        char d[256];
        snprintf(d, sizeof d,
            "{\"total_sessions\":%llu,\"bytes_up\":%llu,\"bytes_down\":%llu,\"errors\":%llu,\"bad_requests\":%llu,\"dropped\":%llu}",
            (unsigned long long)snap.total_sessions,
            (unsigned long long)snap.total_bytes_up,
            (unsigned long long)snap.total_bytes_down,
            (unsigned long long)snap.total_errors,
            (unsigned long long)snap.bad_requests,
            (unsigned long long)snap.dropped_events);
        send_envelope(conn, 200, web_envelope_json(d, NULL, NULL));
        return;
    }
    if (strncmp(uri, "/api/upstreams", 14) == 0) {
        if ((strcmp(method, "POST") == 0 && strstr(uri, "/test")) || (strcmp(method, "GET") == 0 && strstr(uri, "/test"))) {
            int id = parse_id(uri, "/api/upstreams", query);
            pthread_mutex_lock(&srv->lock);
            upstream_profile_t u; int found = 0;
            for (int i = 0; i < srv->upstream_count; i++)
                if (srv->upstreams[i].id == id) { u = srv->upstreams[i]; found = 1; break; }
            pthread_mutex_unlock(&srv->lock);
            if (!found) { send_envelope(conn, 404, web_envelope_json(NULL, "NOT_FOUND", "upstream not found")); return; }
            long lat = -1;
            int rc = upstream_test_reachable(&u, 3000, &lat);
            char d[128];
            snprintf(d, sizeof d, "{\"reachable\":%s,\"latency_ms\":%ld}", rc == 0 ? "true" : "false", lat);
            send_envelope(conn, 200, web_envelope_json(d, NULL, NULL));
            return;
        }
        if (strcmp(method, "POST") == 0) {
            read_body(conn, body, sizeof body);
            cJSON *j = cJSON_Parse(body);
            if (!j) { send_envelope(conn, 400, web_envelope_json(NULL, "BAD_JSON", "bad json")); return; }
            pthread_mutex_lock(&srv->lock);
            int maxid = -1;
            for (int i = 0; i < srv->upstream_count; i++)
                if (srv->upstreams[i].id > maxid) maxid = srv->upstreams[i].id;
            srv->upstreams = realloc(srv->upstreams, (srv->upstream_count + 1) * sizeof(upstream_profile_t));
            upstream_profile_t *u = &srv->upstreams[srv->upstream_count];
            memset(u, 0, sizeof *u);
            u->id = maxid + 1;
            cJSON *v;
            if ((v = cJSON_GetObjectItem(j, "name")) && cJSON_IsString(v)) snprintf(u->name, sizeof u->name, "%s", v->valuestring);
            if ((v = cJSON_GetObjectItem(j, "type")) && cJSON_IsString(v)) u->type = upstream_type_from_str(v->valuestring);
            if ((v = cJSON_GetObjectItem(j, "host")) && cJSON_IsString(v)) snprintf(u->host, sizeof u->host, "%s", v->valuestring);
            if ((v = cJSON_GetObjectItem(j, "port"))) u->port = (uint16_t)v->valueint;
            if ((v = cJSON_GetObjectItem(j, "username")) && cJSON_IsString(v)) snprintf(u->username, sizeof u->username, "%s", v->valuestring);
            if ((v = cJSON_GetObjectItem(j, "password")) && cJSON_IsString(v)) snprintf(u->password, sizeof u->password, "%s", v->valuestring);
            u->enabled = 1;
            if ((v = cJSON_GetObjectItem(j, "enabled"))) u->enabled = cJSON_IsTrue(v);
            int newid = u->id;
            srv->upstream_count++;
            pthread_mutex_unlock(&srv->lock);
            cJSON_Delete(j);
            char d[64]; snprintf(d, sizeof d, "{\"id\":%d}", newid);
            send_envelope(conn, 201, web_envelope_json(d, NULL, NULL));
            return;
        }
        if (strcmp(method, "PUT") == 0) {
            int id = parse_id(uri, "/api/upstreams", query);
            if (id < 0) { send_envelope(conn, 400, web_envelope_json(NULL, "BAD_REQUEST", "missing id")); return; }
            read_body(conn, body, sizeof body);
            char *out = NULL; int status = 200;
            web_upstreams_update(srv, id, body, &out, &status);
            send_envelope(conn, status, out);
            return;
        }
        if (strcmp(method, "DELETE") == 0) {
            int id = parse_id(uri, "/api/upstreams", query);
            pthread_mutex_lock(&srv->lock);
            int idx = -1;
            for (int i = 0; i < srv->upstream_count; i++) if (srv->upstreams[i].id == id) { idx = i; break; }
            if (idx < 0) { pthread_mutex_unlock(&srv->lock); send_envelope(conn, 404, web_envelope_json(NULL, "NOT_FOUND", "upstream not found")); return; }
            for (int i = idx; i < srv->upstream_count - 1; i++) srv->upstreams[i] = srv->upstreams[i+1];
            srv->upstream_count--;
            pthread_mutex_unlock(&srv->lock);
            send_envelope(conn, 200, web_envelope_json("{\"ok\":true}", NULL, NULL));
            return;
        }
        pthread_mutex_lock(&srv->lock);
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < srv->upstream_count; i++) {
            upstream_profile_t *u = &srv->upstreams[i];
            cJSON *o = cJSON_CreateObject();
            cJSON_AddNumberToObject(o, "id", u->id);
            cJSON_AddStringToObject(o, "name", u->name);
            cJSON_AddStringToObject(o, "type", upstream_type_str(u->type));
            cJSON_AddStringToObject(o, "host", u->host);
            cJSON_AddNumberToObject(o, "port", u->port);
            cJSON_AddStringToObject(o, "username", u->username);
            cJSON_AddBoolToObject(o, "has_password", u->password[0] ? 1 : 0);
            cJSON_AddBoolToObject(o, "enabled", u->enabled);
            cJSON_AddItemToArray(arr, o);
        }
        pthread_mutex_unlock(&srv->lock);
        char *s = cJSON_PrintUnformatted(arr);
        send_envelope(conn, 200, web_envelope_json(s ? s : "[]", NULL, NULL));
        if (s) free(s);
        cJSON_Delete(arr);
        return;
    }
    if (strncmp(uri, "/api/rules", 10) == 0) {
        if (strcmp(uri, "/api/rules/reload") == 0 && strcmp(method, "POST") == 0) {
            pthread_mutex_lock(&srv->lock);
            web_rules_reload(&srv->router);
            pthread_mutex_unlock(&srv->lock);
            send_envelope(conn, 200, web_envelope_json("{\"ok\":true}", NULL, NULL));
            return;
        }
        if (strcmp(method, "POST") == 0) {
            read_body(conn, body, sizeof body);
            cJSON *j = cJSON_Parse(body);
            if (!j) { send_envelope(conn, 400, web_envelope_json(NULL, "BAD_JSON", "bad json")); return; }
            rule_t r; memset(&r, 0, sizeof r);
            r.enabled = 1; r.priority = 100;
            cJSON *v;
            if ((v = cJSON_GetObjectItem(j, "domain_pattern")) && cJSON_IsString(v)) snprintf(r.domain_pattern, sizeof r.domain_pattern, "%s", v->valuestring);
            if ((v = cJSON_GetObjectItem(j, "ip_cidr")) && cJSON_IsString(v)) snprintf(r.ip_cidr, sizeof r.ip_cidr, "%s", v->valuestring);
            if ((v = cJSON_GetObjectItem(j, "geo_ip")) && cJSON_IsString(v)) {
                if (!valid_geo(v->valuestring)) { cJSON_Delete(j); send_envelope(conn, 400, web_envelope_json(NULL, "BAD_REQUEST", "geo_ip must be cn, !cn, lan or !lan")); return; }
                snprintf(r.geo_ip, sizeof r.geo_ip, "%s", v->valuestring);
            }
            if ((v = cJSON_GetObjectItem(j, "geo_site")) && cJSON_IsString(v)) {
                if (!valid_geo(v->valuestring)) { cJSON_Delete(j); send_envelope(conn, 400, web_envelope_json(NULL, "BAD_REQUEST", "geo_site must be cn or !cn")); return; }
                snprintf(r.geo_site, sizeof r.geo_site, "%s", v->valuestring);
            }
            if ((v = cJSON_GetObjectItem(j, "port"))) r.port = v->valueint;
            if ((v = cJSON_GetObjectItem(j, "priority"))) r.priority = v->valueint;
            if ((v = cJSON_GetObjectItem(j, "upstream_id"))) r.upstream_id = v->valueint;
            if ((v = cJSON_GetObjectItem(j, "enabled"))) r.enabled = cJSON_IsTrue(v);
            if ((v = cJSON_GetObjectItem(j, "protocol")) && cJSON_IsString(v)) {
                if (strcmp(v->valuestring, "http") == 0) r.protocol = PROTO_HTTP;
                else if (strcmp(v->valuestring, "socks5") == 0 || strcmp(v->valuestring, "socks") == 0) r.protocol = PROTO_SOCKS5;
            }
            if ((v = cJSON_GetObjectItem(j, "name")) && cJSON_IsString(v)) snprintf(r.name, sizeof r.name, "%s", v->valuestring);
            cJSON_Delete(j);
            if (!r.domain_pattern[0] && !r.ip_cidr[0] && !r.geo_ip[0] && !r.geo_site[0]) {
                send_envelope(conn, 400, web_envelope_json(NULL, "BAD_REQUEST", "domain_pattern, ip_cidr or geo condition required"));
                return;
            }
            pthread_mutex_lock(&srv->lock);
            r.id = srv->router.next_rule_id++;
            router_add_rule(&srv->router, &r);
            web_rules_db_save(&r);
            pthread_mutex_unlock(&srv->lock);
            char d[64]; snprintf(d, sizeof d, "{\"id\":%d}", r.id);
            send_envelope(conn, 201, web_envelope_json(d, NULL, NULL));
            return;
        }
        if (strcmp(method, "DELETE") == 0) {
            int id = parse_id(uri, "/api/rules", query);
            pthread_mutex_lock(&srv->lock);
            int rc = router_remove_rule(&srv->router, id);
            if (rc == 0) web_rules_db_delete(id);
            pthread_mutex_unlock(&srv->lock);
            if (rc != 0) send_envelope(conn, 404, web_envelope_json(NULL, "NOT_FOUND", "rule not found"));
            else send_envelope(conn, 200, web_envelope_json("{\"ok\":true}", NULL, NULL));
            return;
        }
        if (strcmp(method, "PUT") == 0) {
            int id = parse_id(uri, "/api/rules", query);
            read_body(conn, body, sizeof body);
            cJSON *j = cJSON_Parse(body);
            if (!j) { send_envelope(conn, 400, web_envelope_json(NULL, "BAD_JSON", "bad json")); return; }
            pthread_mutex_lock(&srv->lock);
            int found = 0;
            for (int i = 0; i < srv->router.count; i++) {
                if (srv->router.rules[i].id == id) {
                    rule_t *r = &srv->router.rules[i];
                    cJSON *v;
                    if ((v = cJSON_GetObjectItem(j, "domain_pattern")) && cJSON_IsString(v)) snprintf(r->domain_pattern, sizeof r->domain_pattern, "%s", v->valuestring);
                    if ((v = cJSON_GetObjectItem(j, "ip_cidr")) && cJSON_IsString(v)) snprintf(r->ip_cidr, sizeof r->ip_cidr, "%s", v->valuestring);
                    if ((v = cJSON_GetObjectItem(j, "geo_ip")) && cJSON_IsString(v)) {
                        if (!valid_geo(v->valuestring)) { pthread_mutex_unlock(&srv->lock); cJSON_Delete(j); send_envelope(conn, 400, web_envelope_json(NULL, "BAD_REQUEST", "geo_ip must be cn, !cn, lan or !lan")); return; }
                        snprintf(r->geo_ip, sizeof r->geo_ip, "%s", v->valuestring);
                    }
                    if ((v = cJSON_GetObjectItem(j, "geo_site")) && cJSON_IsString(v)) {
                        if (!valid_geo(v->valuestring)) { pthread_mutex_unlock(&srv->lock); cJSON_Delete(j); send_envelope(conn, 400, web_envelope_json(NULL, "BAD_REQUEST", "geo_site must be cn or !cn")); return; }
                        snprintf(r->geo_site, sizeof r->geo_site, "%s", v->valuestring);
                    }
                    if ((v = cJSON_GetObjectItem(j, "port"))) r->port = v->valueint;
                    if ((v = cJSON_GetObjectItem(j, "priority"))) r->priority = v->valueint;
                    if ((v = cJSON_GetObjectItem(j, "upstream_id"))) r->upstream_id = v->valueint;
                    if ((v = cJSON_GetObjectItem(j, "enabled"))) r->enabled = cJSON_IsTrue(v);
                    if ((v = cJSON_GetObjectItem(j, "protocol")) && cJSON_IsString(v)) {
                        if (strcmp(v->valuestring, "http") == 0) r->protocol = PROTO_HTTP;
                        else if (strcmp(v->valuestring, "socks5") == 0) r->protocol = PROTO_SOCKS5;
                        else r->protocol = 0;
                    }
                    found = 1;
                    web_rules_db_save(r);
                    break;
                }
            }
            pthread_mutex_unlock(&srv->lock);
            cJSON_Delete(j);
            if (!found) send_envelope(conn, 404, web_envelope_json(NULL, "NOT_FOUND", "rule not found"));
            else send_envelope(conn, 200, web_envelope_json("{\"ok\":true}", NULL, NULL));
            return;
        }
        pthread_mutex_lock(&srv->lock);
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < srv->router.count; i++) {
            rule_t *r = &srv->router.rules[i];
            cJSON *o = cJSON_CreateObject();
            cJSON_AddNumberToObject(o, "id", r->id);
            cJSON_AddNumberToObject(o, "priority", r->priority);
            cJSON_AddBoolToObject(o, "enabled", r->enabled);
            cJSON_AddStringToObject(o, "domain_pattern", r->domain_pattern);
            cJSON_AddStringToObject(o, "geo_ip", r->geo_ip);
            cJSON_AddStringToObject(o, "geo_site", r->geo_site);
            cJSON_AddStringToObject(o, "ip_cidr", r->ip_cidr);
            cJSON_AddNumberToObject(o, "port", r->port);
            const char *ps = "any";
            if (r->protocol == PROTO_HTTP) ps = "http";
            else if (r->protocol == PROTO_SOCKS5) ps = "socks5";
            cJSON_AddStringToObject(o, "protocol", ps);
            cJSON_AddNumberToObject(o, "upstream_id", r->upstream_id);
            cJSON_AddItemToArray(arr, o);
        }
        pthread_mutex_unlock(&srv->lock);
        char *s = cJSON_PrintUnformatted(arr);
        send_envelope(conn, 200, web_envelope_json(s ? s : "[]", NULL, NULL));
        if (s) free(s);
        cJSON_Delete(arr);
        return;
    }
    if (strncmp(uri, "/api/geo", 8) == 0) {
        if (strcmp(uri, "/api/geo/status") == 0 && strcmp(method, "GET") == 0) {
            char *dir W_AUTO_FREE = malloc(512);
            char *p1 W_AUTO_FREE = malloc(1024);
            char *p2 W_AUTO_FREE = malloc(1024);
            char *d W_AUTO_FREE = malloc(1400);
            if (!dir || !p1 || !p2 || !d) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
            if (geo_active_dir(srv->config.geo_dir, dir, 512) != 0) snprintf(dir, 512, ".");
            snprintf(p1, 1024, "%s/geoip.dat", dir);
            snprintf(p2, 1024, "%s/geosite.dat", dir);
            struct stat st1, st2;
            int e1 = stat(p1, &st1), e2 = stat(p2, &st2);
            snprintf(d, 1400,
                "{\"geoip\":{\"exists\":%s,\"size\":%lld,\"mtime\":%lld,\"cn_count\":%zu,\"url\":\"%s\"},"
                "\"geosite\":{\"exists\":%s,\"size\":%lld,\"mtime\":%lld,\"cn_count\":%zu,\"url\":\"%s\"},"
                "\"dir\":\"%s\",\"proxy\":\"%s\"}",
                e1 == 0 ? "true" : "false", e1 == 0 ? (long long)st1.st_size : 0,
                e1 == 0 ? (long long)st1.st_mtime : 0, e1 == 0 ? geo_ip_count() : 0, geo_ip_url(),
                e2 == 0 ? "true" : "false", e2 == 0 ? (long long)st2.st_size : 0,
                e2 == 0 ? (long long)st2.st_mtime : 0, e2 == 0 ? geo_site_count() : 0, geo_site_url(),
                dir, geo_proxy() ? geo_proxy() : "");
            send_envelope(conn, 200, web_envelope_json(d, NULL, NULL));
            return;
        }
        if (strcmp(uri, "/api/geo/download") == 0 && strcmp(method, "POST") == 0) {
            char *dir W_AUTO_FREE = malloc(512);
            if (!dir) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
            if (geo_active_dir(srv->config.geo_dir, dir, 512) != 0) snprintf(dir, 512, ".");
            char *err W_AUTO_FREE = malloc(512);
            if (!err) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
            if (geo_download(dir, err, 512) != 0) {
                char *m W_AUTO_FREE = malloc(640);
                if (!m) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
                snprintf(m, 640, "download failed: %s", err);
                send_envelope(conn, 502, web_envelope_json(NULL, "DOWNLOAD_FAILED", m));
                return;
            }
            send_envelope(conn, 200, web_envelope_json("{\"ok\":true}", NULL, NULL));
            return;
        }
        if (strcmp(uri, "/api/geo/check") == 0 && strcmp(method, "GET") == 0) {
            char *host W_AUTO_FREE = malloc(256);
            if (!host) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
            qstr(query, "host", host, 256);
            if (!host[0]) { send_envelope(conn, 400, web_envelope_json(NULL, "BAD_REQUEST", "host required")); return; }
            char *iplist W_AUTO_FREE = malloc(512);
            if (!iplist) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
            iplist[0] = '\0';
            struct in_addr a4; struct in6_addr a6;
            char *first_ip W_AUTO_FREE = malloc(64);
            if (!first_ip) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
            first_ip[0] = '\0';
            if (inet_pton(AF_INET, host, &a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1) {
                snprintf(iplist, 512, "[\"%s\"]", host);
                snprintf(first_ip, 64, "%s", host);
            } else {
                struct addrinfo hints, *res = NULL;
                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
                if (dns_getaddrinfo(host, "80", &hints, &res) == 0 && res) {
                    char tmp[64]; size_t off = 0; int n = 0;
                    for (struct addrinfo *ai = res; ai && n < 4; ai = ai->ai_next) {
                        void *ap = NULL;
                        if (ai->ai_family == AF_INET) ap = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
                        else if (ai->ai_family == AF_INET6) ap = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
                        else continue;
                        if (!inet_ntop(ai->ai_family, ap, tmp, sizeof tmp)) continue;
                        if (!first_ip[0]) snprintf(first_ip, 64, "%s", tmp);
                        off += (size_t)snprintf(iplist + off, 512 - off, "%s\"%s\"", off ? "," : "[", tmp);
                        n++;
                    }
                    freeaddrinfo(res);
                    if (off) snprintf(iplist + off, 512 - off, "]");
                    else snprintf(iplist, 512, "[]");
                } else snprintf(iplist, 512, "[]");
            }
            int gip = first_ip[0] ? geo_ip_is_cn(first_ip) : -1;
            int gsite = geo_site_is_cn(host);
            int matched = -1, upid = -1;
            char *upname W_AUTO_FREE = malloc(128);
            if (!upname) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
            upname[0] = '\0';
            pthread_mutex_lock(&srv->lock);
            matched = router_select_rule_id(&srv->router, host, 80, 0, NULL);
            int want_up = router_select(&srv->router, host, 80, 0, NULL);
            if (want_up < 0) { /* 默认出口：名字匹配 default_upstream，找不到用第一个 */
                for (int i = 0; i < srv->upstream_count; i++)
                    if (strcmp(srv->upstreams[i].name, srv->router.default_upstream) == 0) { want_up = srv->upstreams[i].id; break; }
                if (want_up < 0 && srv->upstream_count) want_up = srv->upstreams[0].id;
            }
            for (int i = 0; i < srv->upstream_count; i++)
                if (srv->upstreams[i].id == want_up) { upid = want_up; snprintf(upname, 128, "%s", srv->upstreams[i].name); break; }
            pthread_mutex_unlock(&srv->lock);
            char *gd W_AUTO_FREE = malloc(2048);
            if (!gd) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
            snprintf(gd, 2048,
                "{\"host\":\"%s\",\"ips\":%s,\"geoip_cn\":%s,\"geosite_cn\":%s,\"db_loaded\":%s,\"matched_rule\":%d,\"upstream\":{\"id\":%d,\"name\":\"%s\"}}",
                host, iplist,
                gip < 0 ? "null" : (gip == 1 ? "true" : "false"),
                gsite < 0 ? "null" : (gsite == 1 ? "true" : "false"),
                geo_db_loaded() ? "true" : "false",
                matched, upid, upname);
            send_envelope(conn, 200, web_envelope_json(gd, NULL, NULL));
            return;
        }
        send_envelope(conn, 404, web_envelope_json(NULL, "NOT_FOUND", "unknown geo endpoint"));
        return;
    }
    if (strncmp(uri, "/api/sessions", 13) == 0) {
        if (strcmp(method, "GET") == 0 && strncmp(uri, "/api/sessions/", 14) == 0) {
            long long id = atoll(uri + 14);
            char *one W_AUTO_FREE = malloc(2048);
            if (!one) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
            int rc = db_get_session_by_id(id, one, 2048);
            if (rc != 0) { send_envelope(conn, 404, web_envelope_json(NULL, "NOT_FOUND", "session not found")); return; }
            send_envelope(conn, 200, web_envelope_json(one, NULL, NULL));
            return;
        }
        char *client W_AUTO_FREE = malloc(140);
        char *target W_AUTO_FREE = malloc(520);
        if (!client || !target) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
        qstr(query, "client", client, 140);
        qstr(query, "target", target, 520);
        long long up = qnum(query, "upstream");
        int has_up = (strstr(query ? query : "", "upstream=") != NULL);
        int limit = (int)qnum(query, "limit"); if (limit <= 0) limit = 100;
        int offset = (int)qnum(query, "offset");
        if (up < 0) has_up = 0;
        if (db_query_sessions(client[0] ? client : NULL, target[0] ? target : NULL,
                has_up ? (int)up : -1, limit, offset, tmp, tmpsz, NULL) != 0) {
            send_envelope(conn, 500, web_envelope_json(NULL, "DB_ERROR", "query failed"));
            return;
        }
        send_envelope(conn, 200, web_envelope_paged(tmp));
        return;
    }
    if (strncmp(uri, "/api/stats", 10) == 0) {
        if (strcmp(uri, "/api/stats/summary") == 0) {
            long long from = qnum(query, "from"), to = qnum(query, "to");
            if (db_stats_summary(from, to, tmp, tmpsz) != 0) {
                send_envelope(conn, 500, web_envelope_json(NULL, "DB_ERROR", "query failed"));
                return;
            }
            send_envelope(conn, 200, web_envelope_json(tmp, NULL, NULL));
            return;
        }
        if (strcmp(uri, "/api/stats/daily") == 0) {
            int days = (int)qnum(query, "days"); if (days <= 0) days = 30;
            if (db_stats_daily(days, tmp, tmpsz) != 0) {
                send_envelope(conn, 500, web_envelope_json(NULL, "DB_ERROR", "query failed"));
                return;
            }
            send_envelope(conn, 200, web_envelope_json(tmp, NULL, NULL));
            return;
        }
        if (strcmp(uri, "/api/stats/top") == 0) {
            char *by W_AUTO_FREE = malloc(16);
            if (!by) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
            qstr(query, "by", by, 16);
            if (!by[0]) snprintf(by, 16, "target");
            int limit = (int)qnum(query, "limit"); if (limit <= 0) limit = 20;
            long long from = qnum(query, "from"), to = qnum(query, "to");
            int rc = db_stats_top(by, limit, from, to, tmp, tmpsz);
            if (rc == -2) { send_envelope(conn, 400, web_envelope_json(NULL, "BAD_REQUEST", "by must be target|client")); return; }
            if (rc != 0) { send_envelope(conn, 500, web_envelope_json(NULL, "DB_ERROR", "query failed")); return; }
            send_envelope(conn, 200, web_envelope_json(tmp, NULL, NULL));
            return;
        }
    }
    if (strncmp(uri, "/api/settings", 13) == 0) {
        if (strcmp(method, "PUT") == 0) {
            read_body(conn, body, sizeof body);
            cJSON *j = cJSON_Parse(body);
            if (!j || !cJSON_IsObject(j)) {
                if (j) cJSON_Delete(j);
                send_envelope(conn, 400, web_envelope_json(NULL, "BAD_JSON", "bad json"));
                return;
            }
            for (cJSON *c = j->child; c; c = c->next) {
                if (c->string && cJSON_IsString(c))
                    db_settings_set(c->string, c->valuestring);
            }
            cJSON_Delete(j);
            send_envelope(conn, 200, web_envelope_json("{\"ok\":true}", NULL, NULL));
            return;
        }
        if (db_settings_get(tmp, tmpsz) != 0) {
            send_envelope(conn, 500, web_envelope_json(NULL, "DB_ERROR", "query failed"));
            return;
        }
        send_envelope(conn, 200, web_envelope_json(tmp, NULL, NULL));
        return;
    }
    if (strncmp(uri, "/api/dns", 8) == 0) {
        if (strcmp(uri, "/api/dns/status") == 0 && strcmp(method, "GET") == 0) {
            char d[512];
            snprintf(d, sizeof d,
                "{\"proxy\":\"%s\",\"cache_count\":%zu,\"log_count\":%zu,\"fallback\":[\"1.1.1.1\",\"8.8.8.8\"]}",
                dns_get_proxy() ? dns_get_proxy() : "none",
                dns_cache_count(), dns_log_count());
            send_envelope(conn, 200, web_envelope_json(d, NULL, NULL));
            return;
        }
        if (strcmp(uri, "/api/dns/nameservers") == 0 && strcmp(method, "GET") == 0) {
            dns_ns_t *ns W_AUTO_FREE = malloc(sizeof(dns_ns_t) * 16);
            int n = 0;
            if (!ns) { send_envelope(conn, 500, web_envelope_json(NULL, "ERR", "oom")); return; }
            dns_get_nameservers(ns, 16, &n);
            char *arr = malloc(4096);
            if (!arr) { send_envelope(conn, 500, web_envelope_json(NULL, "ERR", "oom")); return; }
            size_t off = 0;
            off += snprintf(arr + off, 4096 - off, "[");
            for (int i = 0; i < n && off < 4000; i++) {
                off += snprintf(arr + off, 4096 - off,
                    "%s{\"type\":%d,\"url\":\"%s\",\"host\":\"%s\",\"proxy\":\"%s\"}",
                    i ? "," : "", (int)ns[i].type, ns[i].url, ns[i].host, ns[i].proxy);
            }
            off += snprintf(arr + off, 4096 - off, "]");
            char *d = malloc(off + 32);
            if (!d) { free(arr); send_envelope(conn, 500, web_envelope_json(NULL, "ERR", "oom")); return; }
            snprintf(d, off + 32, "{\"nameservers\":%s}", arr);
            free(arr);
            char *env = web_envelope_json(d, NULL, NULL);
            free(d);
            send_envelope(conn, 200, env);
            return;
        }
        if (strcmp(uri, "/api/dns/nameservers") == 0 && strcmp(method, "POST") == 0) {
            send_envelope(conn, 200, web_envelope_json("{\"ok\":true}", NULL, NULL));
            return;
        }
        if (strcmp(uri, "/api/dns/proxy") == 0 && (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0)) {
            send_envelope(conn, 200, web_envelope_json("{\"ok\":true}", NULL, NULL));
            return;
        }
        if (strcmp(uri, "/api/dns/cache") == 0 && strcmp(method, "GET") == 0) {
            dns_cache_entry_t *ent W_AUTO_FREE = malloc(sizeof(dns_cache_entry_t) * 256);
            size_t n = 0;
            if (!ent) { send_envelope(conn, 500, web_envelope_json(NULL, "ERR", "oom")); return; }
            dns_cache_list(ent, 256, &n);
            char *arr = malloc(8192);
            if (!arr) { send_envelope(conn, 500, web_envelope_json(NULL, "ERR", "oom")); return; }
            size_t off = 0;
            off += snprintf(arr + off, 8192 - off, "[");
            time_t now = time(NULL);
            for (size_t i = 0; i < n && off < 8000; i++) {
                long left = ent[i].expire_at > now ? (long)(ent[i].expire_at - now) : 0;
                off += snprintf(arr + off, 8192 - off,
                    "%s{\"domain\":\"%s\",\"class\":%d,\"resolver_id\":\"%s\",\"ip\":\"%s\",\"ttl_left\":%ld,\"hits\":%u,\"negative\":%s}",
                    i ? "," : "",
                    ent[i].domain,
                    (int)ent[i].class,
                    ent[i].resolver_id,
                    ent[i].ip_n > 0 ? ent[i].ips[0] : "",
                    left,
                    ent[i].hits,
                    ent[i].negative ? "true" : "false");
            }
            off += snprintf(arr + off, 8192 - off, "]");
            char *d = malloc(off + 32);
            if (!d) { free(arr); send_envelope(conn, 500, web_envelope_json(NULL, "ERR", "oom")); return; }
            snprintf(d, off + 32, "{\"cache\":%s}", arr);
            free(arr);
            char *env = web_envelope_json(d, NULL, NULL);
            free(d);
            send_envelope(conn, 200, env);
            return;
        }
        if (strcmp(uri, "/api/dns/cache/flush") == 0 && strcmp(method, "POST") == 0) {
            dns_cache_flush();
            send_envelope(conn, 200, web_envelope_json("{\"ok\":true}", NULL, NULL));
            return;
        }
        if (strcmp(uri, "/api/dns/logs") == 0 && strcmp(method, "GET") == 0) {
            dns_req_log_t *dlog W_AUTO_FREE = malloc(sizeof(dns_req_log_t) * 256);
            size_t n = 0;
            if (!dlog) { send_envelope(conn, 500, web_envelope_json(NULL, "ERR", "oom")); return; }
            dns_log_list(dlog, 256, &n);
            char *arr = malloc(8192);
            if (!arr) { send_envelope(conn, 500, web_envelope_json(NULL, "ERR", "oom")); return; }
            size_t off = 0;
            off += snprintf(arr + off, 8192 - off, "[");
            for (size_t i = 0; i < n && off < 8000; i++) {
                off += snprintf(arr + off, 8192 - off,
                    "%s{\"ts\":%ld,\"domain\":\"%s\",\"class\":%d,\"resolver_id\":\"%s\",\"via_proxy\":%s,\"duration_ms\":%ld,\"status\":\"%s\",\"ip_count\":%d,\"from_cache\":%s}",
                    i ? "," : "",
                    (long)dlog[i].ts,
                    dlog[i].domain,
                    (int)dlog[i].class,
                    dlog[i].resolver_id,
                    dlog[i].via_proxy ? "true" : "false",
                    dlog[i].duration_ms,
                    dlog[i].status,
                    dlog[i].ip_count,
                    dlog[i].from_cache ? "true" : "false");
            }
            off += snprintf(arr + off, 8192 - off, "]");
            char *d = malloc(off + 32);
            if (!d) { free(arr); send_envelope(conn, 500, web_envelope_json(NULL, "ERR", "oom")); return; }
            snprintf(d, off + 32, "{\"logs\":%s}", arr);
            free(arr);
            char *env = web_envelope_json(d, NULL, NULL);
            free(d);
            send_envelope(conn, 200, env);
            return;
        }
        if (strcmp(uri, "/api/dns/logs/clear") == 0 && strcmp(method, "POST") == 0) {
            dns_log_clear();
            send_envelope(conn, 200, web_envelope_json("{\"ok\":true}", NULL, NULL));
            return;
        }
        send_envelope(conn, 404, web_envelope_json(NULL, "NOT_FOUND", "unknown dns api"));
        return;
    }

    if (strncmp(uri, "/api/logs", 9) == 0) {
        char *level W_AUTO_FREE = malloc(16);
        if (!level) { send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "alloc")); return; }
        qstr(query, "level", level, 16);
        int limit = (int)qnum(query, "limit"); if (limit <= 0) limit = 100;
        if (web_log_query(level[0] ? level : NULL, limit, tmp, tmpsz) != 0) {
            send_envelope(conn, 500, web_envelope_json(NULL, "INTERNAL", "log query failed"));
            return;
        }
        send_envelope(conn, 200, web_envelope_json(tmp, NULL, NULL));
        return;
    }
    send_envelope(conn, 404, web_envelope_json(NULL, "NOT_FOUND", "unknown api"));
}
