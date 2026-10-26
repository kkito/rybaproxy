#ifndef RYBAPROXY_SESSION_H
#define RYBAPROXY_SESSION_H

#include "rybaproxy/common.h"
#include <stdint.h>
#include <time.h>
#include <event2/event.h>
#include <event2/bufferevent.h>

typedef enum {
    SESS_ACTIVE = 0,
    SESS_DONE = 1,
    SESS_ERROR = 2,
    SESS_TIMEOUT = 3
} session_status_t;

typedef struct session {
    uint64_t id;
    protocol_t protocol;
    char client_ip[64];
    char target_host[256];
    uint16_t target_port;
    char method[16];
    int upstream_id;
    session_status_t status;
    int error_code;
    char error_msg[128];
    uint64_t bytes_up;
    uint64_t bytes_down;
    time_t started_at;
    time_t ended_at;
    struct bufferevent *bev_client;
    struct bufferevent *bev_upstream;
    struct event *timeout_ev;
    struct event_base *base;
    void *user_data;
} session_t;

session_t *session_create(struct event_base *base, protocol_t proto, const char *client_ip);
void session_destroy(session_t *s);
void session_set_target(session_t *s, const char *host, uint16_t port);
void session_set_method(session_t *s, const char *method);
void session_finish(session_t *s, session_status_t status, int err, const char *msg);

#endif
