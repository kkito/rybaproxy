#include "rybaproxy/web.h"
#include "rybaproxy/web_api.h"
#include "web_page.h"

#include <civetweb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int begin_request(struct mg_connection *conn) {
    const struct mg_request_info *ri = mg_get_request_info(conn);
    server_ctx_t *srv = (server_ctx_t *)mg_get_user_context_data(conn);
    const char *uri = ri->request_uri ? ri->request_uri : "/";
    const char *method = ri->request_method ? ri->request_method : "GET";
    const char *qs = ri->query_string ? ri->query_string : "";
    /* strip query from request_uri if present */
    char path[1024];
    snprintf(path, sizeof path, "%s", uri);
    char *qm = strchr(path, '?');
    if (qm) *qm = '\0';

    if (strcmp(path, "/healthz") == 0 || strncmp(path, "/api/", 5) == 0) {
        web_api_dispatch(conn, srv, path, method, qs);
    } else {
        mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
                  (int)strlen(WEB_PAGE_HTML));
        mg_write(conn, WEB_PAGE_HTML, strlen(WEB_PAGE_HTML));
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
