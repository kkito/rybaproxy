#include "rybaproxy/web.h"
#include "rybaproxy/stats.h"
#include "rybaproxy/db.h"
#include "rybaproxy/router.h"
#include "rybaproxy/upstream.h"

#include <civetweb.h>
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char INDEX_HTML[] =
"<!DOCTYPE html><html><head><meta charset=utf-8><title>rybaproxy admin</title></head>"
"<body><h1>rybaproxy admin</h1>"
"<p>Endpoints: /api/stats, /api/upstreams, /api/rules, /api/sessions</p></body></html>";

static void send_json(struct mg_connection *conn, int status, const char *body) {
    mg_printf(conn, "HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
              status, (int)strlen(body));
    mg_write(conn, body, strlen(body));
}

static void handle_stats(struct mg_connection *conn, server_ctx_t *srv) {
    (void)srv;
    stats_snapshot_t snap = stats_get();
    char buf[512];
    snprintf(buf, sizeof buf,
        "{\"total_sessions\":%llu,\"bytes_up\":%llu,\"bytes_down\":%llu,\"errors\":%llu,\"bad_requests\":%llu,\"dropped\":%llu}",
        (unsigned long long)snap.total_sessions,
        (unsigned long long)snap.total_bytes_up,
        (unsigned long long)snap.total_bytes_down,
        (unsigned long long)snap.total_errors,
        (unsigned long long)snap.bad_requests,
        (unsigned long long)snap.dropped_events);
    send_json(conn, 200, buf);
}

static void handle_upstreams(struct mg_connection *conn, server_ctx_t *srv) {
    pthread_mutex_lock(&srv->lock);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < srv->upstream_count; i++) {
        upstream_profile_t *u = &srv->upstreams[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", u->id);
        cJSON_AddStringToObject(o, "name", u->name);
        cJSON_AddNumberToObject(o, "type", (double)u->type);
        cJSON_AddStringToObject(o, "host", u->host);
        cJSON_AddNumberToObject(o, "port", u->port);
        cJSON_AddBoolToObject(o, "enabled", u->enabled);
        cJSON_AddItemToArray(arr, o);
    }
    pthread_mutex_unlock(&srv->lock);
    char *s = cJSON_PrintUnformatted(arr);
    send_json(conn, 200, s ? s : "[]");
    if (s) free(s);
    cJSON_Delete(arr);
}

static void handle_rules_list(struct mg_connection *conn, server_ctx_t *srv) {
    pthread_mutex_lock(&srv->lock);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < srv->router.count; i++) {
        rule_t *r = &srv->router.rules[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", r->id);
        cJSON_AddNumberToObject(o, "priority", r->priority);
        cJSON_AddBoolToObject(o, "enabled", r->enabled);
        cJSON_AddStringToObject(o, "domain_pattern", r->domain_pattern);
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
    send_json(conn, 200, s ? s : "[]");
    if (s) free(s);
    cJSON_Delete(arr);
}

static void handle_rules_add(struct mg_connection *conn, server_ctx_t *srv) {
    char buf[4096];
    int n = mg_read(conn, buf, sizeof buf - 1);
    if (n < 0) n = 0;
    buf[n] = '\0';
    cJSON *j = cJSON_Parse(buf);
    if (!j) { send_json(conn, 400, "{\"error\":\"bad json\"}"); return; }
    rule_t r; memset(&r, 0, sizeof r);
    r.enabled = 1;
    r.priority = 100;
    r.port = 0;
    r.protocol = 0;
    cJSON *v;
    if ((v = cJSON_GetObjectItem(j, "domain_pattern")) && cJSON_IsString(v)) snprintf(r.domain_pattern, sizeof r.domain_pattern, "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(j, "ip_cidr")) && cJSON_IsString(v)) snprintf(r.ip_cidr, sizeof r.ip_cidr, "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(j, "port"))) r.port = v->valueint;
    if ((v = cJSON_GetObjectItem(j, "priority"))) r.priority = v->valueint;
    if ((v = cJSON_GetObjectItem(j, "upstream_id"))) r.upstream_id = v->valueint;
    if ((v = cJSON_GetObjectItem(j, "protocol")) && cJSON_IsString(v)) {
        if (strcmp(v->valuestring, "http") == 0) r.protocol = PROTO_HTTP;
        else if (strcmp(v->valuestring, "socks5") == 0 || strcmp(v->valuestring, "socks") == 0) r.protocol = PROTO_SOCKS5;
        else r.protocol = 0;
    }
    if ((v = cJSON_GetObjectItem(j, "name")) && cJSON_IsString(v)) snprintf(r.name, sizeof r.name, "%s", v->valuestring);
    cJSON_Delete(j);

    pthread_mutex_lock(&srv->lock);
    r.id = srv->router.next_rule_id++;
    router_add_rule(&srv->router, &r);
    pthread_mutex_unlock(&srv->lock);

    char out[128];
    snprintf(out, sizeof out, "{\"id\":%d}", r.id);
    send_json(conn, 201, out);
}

static void handle_rules_delete(struct mg_connection *conn, server_ctx_t *srv) {
    const struct mg_request_info *ri = mg_get_request_info(conn);
    const char *qs = ri->query_string ? ri->query_string : "";
    char val[32]; val[0] = '\0';
    mg_get_var(qs, strlen(qs), "id", val, sizeof val);
    int id = atoi(val);
    pthread_mutex_lock(&srv->lock);
    int rc = router_remove_rule(&srv->router, id);
    pthread_mutex_unlock(&srv->lock);
    if (rc != 0) send_json(conn, 404, "{\"error\":\"not found\"}");
    else send_json(conn, 200, "{\"ok\":true}");
}

static void handle_sessions(struct mg_connection *conn, server_ctx_t *srv) {
    (void)srv;
    char buf[65536];
    /* default limit 100 */
    const struct mg_request_info *ri = mg_get_request_info(conn);
    int limit = 100;
    if (ri->query_string) {
        char v[32]; v[0]='\0';
        mg_get_var(ri->query_string, strlen(ri->query_string), "limit", v, sizeof v);
        if (v[0]) limit = atoi(v);
    }
    if (db_get_recent_sessions(limit, buf, sizeof buf) != 0) {
        send_json(conn, 500, "{\"error\":\"db\"}");
        return;
    }
    send_json(conn, 200, buf);
}

static int begin_request(struct mg_connection *conn) {
    const struct mg_request_info *ri = mg_get_request_info(conn);
    server_ctx_t *srv = (server_ctx_t *)mg_get_user_context_data(conn);
    const char *uri = ri->request_uri ? ri->request_uri : "/";
    const char *method = ri->request_method ? ri->request_method : "GET";

    if (strcmp(uri, "/api/stats") == 0) {
        handle_stats(conn, srv);
    } else if (strcmp(uri, "/api/upstreams") == 0) {
        handle_upstreams(conn, srv);
    } else if (strcmp(uri, "/api/rules") == 0) {
        if (strcmp(method, "POST") == 0) handle_rules_add(conn, srv);
        else if (strcmp(method, "DELETE") == 0) handle_rules_delete(conn, srv);
        else handle_rules_list(conn, srv);
    } else if (strncmp(uri, "/api/sessions", 13) == 0) {
        handle_sessions(conn, srv);
    } else {
        mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
                  (int)strlen(INDEX_HTML));
        mg_write(conn, INDEX_HTML, strlen(INDEX_HTML));
    }
    return 1;
}

struct mg_context *web_start(server_ctx_t *srv, int port) {
    char portstr[32];
    snprintf(portstr, sizeof portstr, "%d", port);
    const char *options[] = { "listening_ports", portstr, "num_threads", "4", NULL };
    struct mg_callbacks cbs;
    memset(&cbs, 0, sizeof cbs);
    cbs.begin_request = begin_request;
    return mg_start(&cbs, srv, options);
}

void web_stop(struct mg_context *ctx) {
    if (ctx) mg_stop(ctx);
}
