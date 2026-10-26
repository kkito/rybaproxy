#include "rybaproxy/session.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t next_id = 1;

session_t *session_create(struct event_base *base, protocol_t proto, const char *client_ip) {
    session_t *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->id = next_id++;
    s->protocol = proto;
    s->base = base;
    s->started_at = time(NULL);
    s->status = SESS_ACTIVE;
    if (client_ip) snprintf(s->client_ip, sizeof s->client_ip, "%s", client_ip);
    return s;
}

void session_destroy(session_t *s) {
    if (!s) return;
    if (s->bev_client) bufferevent_free(s->bev_client);
    if (s->bev_upstream) bufferevent_free(s->bev_upstream);
    if (s->timeout_ev) event_free(s->timeout_ev);
    free(s);
}

void session_set_target(session_t *s, const char *host, uint16_t port) {
    if (!s || !host) return;
    snprintf(s->target_host, sizeof s->target_host, "%s", host);
    s->target_port = port;
}

void session_set_method(session_t *s, const char *method) {
    if (!s || !method) return;
    snprintf(s->method, sizeof s->method, "%s", method);
}

void session_finish(session_t *s, session_status_t status, int err, const char *msg) {
    if (!s) return;
    s->status = status;
    s->error_code = err;
    s->ended_at = time(NULL);
    if (msg) snprintf(s->error_msg, sizeof s->error_msg, "%s", msg);
}
