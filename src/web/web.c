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
"<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>rybaproxy admin</title>\n<style>\nbody { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 20px; background:#f5f7fa; color:#222; }\nh1 { color:#333; }\n.card { background:#fff; padding:16px; margin:12px 0; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,.1); }\ntable { width:100%; border-collapse:collapse; }\nth,td { padding:8px; border-bottom:1px solid #eee; text-align:left; font-size:14px; }\nbutton { padding:6px 12px; cursor:pointer; }\ninput, select { padding:6px; margin:4px; }\n#stats { font-size:16px; }\n</style>\n</head>\n<body>\n<h1>rybaproxy 管理面板</h1>\n<div class=\"card\">\n<h2>实时统计</h2>\n<div id=\"stats\">加载中...</div>\n</div>\n<div class=\"card\">\n<h2>上游列表</h2>\n<table id=\"upstreams\"><thead><tr><th>ID</th><th>名称</th><th>类型</th><th>主机</th><th>端口</th><th>启用</th></tr></thead><tbody></tbody></table>\n</div>\n<div class=\"card\">\n<h2>路由规则</h2>\n<form id=\"ruleForm\">\n<input name=\"domain_pattern\" placeholder=\"域名模式\" />\n<input name=\"ip_cidr\" placeholder=\"IP/CIDR\" />\n<input name=\"port\" type=\"number\" placeholder=\"端口\" />\n<input name=\"priority\" type=\"number\" placeholder=\"优先级\" value=\"100\" />\n<input name=\"upstream_id\" type=\"number\" placeholder=\"上游ID\" value=\"0\" />\n<select name=\"protocol\"><option value=\"any\">any</option><option value=\"http\">http</option><option value=\"socks5\">socks5</option></select>\n<button type=\"submit\">添加规则</button>\n</form>\n<table id=\"rules\"><thead><tr><th>ID</th><th>优先级</th><th>域名</th><th>IP/CIDR</th><th>端口</th><th>协议</th><th>上游</th><th>操作</th></tr></thead><tbody></tbody></table>\n</div>\n<div class=\"card\">\n<h2>最近会话</h2>\n<table id=\"sessions\"><thead><tr><th>ID</th><th>协议</th><th>客户端</th><th>目标</th><th>状态</th><th>上行</th><th>下行</th></tr></thead><tbody></tbody></table>\n</div>\n<script>\nasync function fetchJSON(url, opts){ const r=await fetch(url,opts); return r.json(); }\nasync function loadStats(){\n  const d=await fetchJSON('/api/stats');\n  document.getElementById('stats').innerHTML =\n    '总会话: ' + d.total_sessions + ' | 上行: ' + d.bytes_up + ' | 下行: ' + d.bytes_down + ' | 错误: ' + d.errors + ' | 丢弃: ' + d.dropped;\n}\nasync function loadUpstreams(){\n  const d=await fetchJSON('/api/upstreams');\n  const tb=document.querySelector('#upstreams tbody');\n  tb.innerHTML=d.map(u=>'<tr><td>'+u.id+'</td><td>'+(u.name||'')+'</td><td>'+u.type+'</td><td>'+(u.host||'')+'</td><td>'+(u.port||'')+'</td><td>'+u.enabled+'</td></tr>').join('');\n}\nasync function loadRules(){\n  const d=await fetchJSON('/api/rules');\n  const tb=document.querySelector('#rules tbody');\n  tb.innerHTML=d.map(r=>'<tr><td>'+r.id+'</td><td>'+r.priority+'</td><td>'+(r.domain_pattern||'')+'</td><td>'+(r.ip_cidr||'')+'</td><td>'+r.port+'</td><td>'+r.protocol+'</td><td>'+r.upstream_id+'</td><td><button onclick=\"delRule('+r.id+')\">删除</button></td></tr>').join('');\n}\nasync function delRule(id){\n  await fetch('/api/rules?id='+id,{method:'DELETE'});\n  loadRules();\n}\ndocument.getElementById('ruleForm').addEventListener('submit', async e=>{\n  e.preventDefault();\n  const f=e.target;\n  const data={\n    domain_pattern:f.domain_pattern.value,\n    ip_cidr:f.ip_cidr.value,\n    port:parseInt(f.port.value||0),\n    priority:parseInt(f.priority.value||100),\n    upstream_id:parseInt(f.upstream_id.value||0),\n    protocol:f.protocol.value\n  };\n  await fetch('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});\n  f.reset();\n  loadRules();\n});\nasync function loadSessions(){\n  const d=await fetchJSON('/api/sessions?limit=50');\n  const tb=document.querySelector('#sessions tbody');\n  tb.innerHTML=d.map(s=>'<tr><td>'+s.id+'</td><td>'+s.protocol+'</td><td>'+s.client_ip+'</td><td>'+s.target_host+':'+s.target_port+'</td><td>'+s.status+'</td><td>'+s.bytes_up+'</td><td>'+s.bytes_down+'</td></tr>').join('');\n}\nfunction refresh(){ loadStats(); loadUpstreams(); loadRules(); loadSessions(); }\nrefresh();\nsetInterval(refresh, 5000);\n</script>\n</body>\n</html>\n";

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
