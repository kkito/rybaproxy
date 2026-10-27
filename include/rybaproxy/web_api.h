#ifndef RYBAPROXY_WEB_API_H
#define RYBAPROXY_WEB_API_H

#include "rybaproxy/server.h"

struct mg_connection;

/* envelope builders (malloc'd, caller frees) */
char *web_envelope_json(const char *data_json, const char *err_code, const char *err_msg);
char *web_envelope_paged(const char *inner_paged_json);

/* pure logic helpers (unit-testable, no socket) */
int web_rules_reload(router_t *r);
/* geo 值白名单：""/"cn"/"!cn" 合法 */
int valid_geo(const char *s);
int web_upstreams_update(server_ctx_t *srv, int id, const char *body, char **out_envelope, int *out_status);

/* ring log */
void web_log_push(const char *level, const char *msg);
int web_log_query(const char *level, int limit, char *buf, size_t bufsz);

/* dispatcher: parses uri+method, writes full HTTP response */
void web_api_dispatch(struct mg_connection *conn, server_ctx_t *srv, const char *uri, const char *method, const char *query);

#endif
