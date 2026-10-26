#include "rybaproxy/relay.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <string.h>

static void pump(struct bufferevent *src, struct bufferevent *dst, uint64_t *counter) {
    struct evbuffer *in = bufferevent_get_input(src);
    struct evbuffer *out = bufferevent_get_output(dst);
    size_t len = evbuffer_get_length(in);
    if (len == 0) return;
    evbuffer_add_buffer(out, in);
    *counter += (uint64_t)len;
}

static void client_read_cb(struct bufferevent *bev, void *ctx) {
    session_t *s = ctx;
    pump(bev, s->bev_upstream, &s->bytes_up);
}

static void upstream_read_cb(struct bufferevent *bev, void *ctx) {
    session_t *s = ctx;
    pump(bev, s->bev_client, &s->bytes_down);
}

static void event_cb(struct bufferevent *bev, short events, void *ctx) {
    session_t *s = ctx;
    (void)bev;
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        session_finish(s, (events & BEV_EVENT_TIMEOUT) ? SESS_TIMEOUT : SESS_DONE, 0, NULL);
    }
}

void relay_start(session_t *s, struct bufferevent *client, struct bufferevent *upstream) {
    s->bev_client = client;
    s->bev_upstream = upstream;
    bufferevent_setcb(client, client_read_cb, NULL, event_cb, s);
    bufferevent_setcb(upstream, upstream_read_cb, NULL, event_cb, s);
    bufferevent_enable(client, EV_READ | EV_WRITE);
    bufferevent_enable(upstream, EV_READ | EV_WRITE);
}
