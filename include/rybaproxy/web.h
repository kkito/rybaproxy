#ifndef RYBAPROXY_WEB_H
#define RYBAPROXY_WEB_H

#include "rybaproxy/server.h"

struct mg_context *web_start(server_ctx_t *srv, int port);
void web_stop(struct mg_context *ctx);

#endif
