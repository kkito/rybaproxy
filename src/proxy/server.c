#include "rybaproxy/server.h"

#include "rybaproxy/auth.h"
#include "rybaproxy/config.h"
#include "rybaproxy/http_proxy.h"
#include "rybaproxy/relay.h"
#include "rybaproxy/router.h"
#include "rybaproxy/socks5.h"
#include "rybaproxy/upstream.h"
#include "rybaproxy/session.h"
#include "rybaproxy/stats.h"
#include "rybaproxy/db.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/util.h>

typedef struct {
    int headers_done;
    int is_connect;
    http_request_info_t info;
    char reqbuf[16384];
    size_t req_len;
} http_conn_t;

typedef struct {
    int state; /* 0 handshake,1 auth,2 request */
} socks_conn_t;

typedef struct {
    server_ctx_t *srv;
    session_t *session;
    int is_http;
    http_conn_t http;
    socks_conn_t socks;
} conn_t;

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void get_client_ip(struct bufferevent *bev, char *buf, size_t sz) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof ss;
    int fd = bufferevent_getfd(bev);
    if (getpeername(fd, (struct sockaddr*)&ss, &slen) == 0) {
        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in*)&ss;
            inet_ntop(AF_INET, &sin->sin_addr, buf, sz);
        } else if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&ss;
            inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sz);
        } else snprintf(buf, sz, "unknown");
    } else snprintf(buf, sz, "unknown");
}

static upstream_profile_t *find_upstream_by_name(server_ctx_t *ctx, const char *name) {
    for (int i = 0; i < ctx->upstream_count; i++)
        if (strcmp(ctx->upstreams[i].name, name) == 0) return &ctx->upstreams[i];
    return NULL;
}

static upstream_profile_t *find_upstream_by_id(server_ctx_t *ctx, int id) {
    for (int i = 0; i < ctx->upstream_count; i++)
        if (ctx->upstreams[i].id == id) return &ctx->upstreams[i];
    return ctx->upstream_count ? &ctx->upstreams[0] : NULL;
}

static int ensure_direct(server_ctx_t *ctx) {
    for (int i = 0; i < ctx->upstream_count; i++)
        if (ctx->upstreams[i].type == UPSTREAM_DIRECT) return 0;
    ctx->upstreams = realloc(ctx->upstreams, (ctx->upstream_count + 1) * sizeof(upstream_profile_t));
    upstream_profile_t *p = &ctx->upstreams[ctx->upstream_count++];
    memset(p, 0, sizeof *p);
    p->id = ctx->upstream_count - 1;
    strcpy(p->name, "direct");
    p->type = UPSTREAM_DIRECT;
    p->enabled = 1;
    return 0;
}

static int upstream_connect_profile(upstream_profile_t *up, const char *host, uint16_t port, int *fd) {
    if (!up) return -1;
    if (up->type == UPSTREAM_DIRECT) return upstream_connect_direct(host, port, fd);
    if (up->type == UPSTREAM_HTTP) return upstream_connect_http(up, host, port, fd);
    if (up->type == UPSTREAM_SOCKS5) return upstream_connect_socks5(up, host, port, fd);
    return -1;
}

/* ---------- HTTP handling ---------- */

static void http_finish(conn_t *c, int status) {
    (void)status;
    if (c->session) {
        if (c->session->bev_client) bufferevent_setcb(c->session->bev_client, NULL, NULL, NULL, NULL);
        if (c->session->bev_upstream) bufferevent_setcb(c->session->bev_upstream, NULL, NULL, NULL, NULL);
        c->session->user_data = NULL;
        stats_record_session(c->session);
        const char *up_name = "direct";
        if (c->srv) {
            upstream_profile_t *up = find_upstream_by_id(c->srv, c->session->upstream_id);
            if (up) up_name = up->name;
        }
        db_enqueue_session(c->session, up_name);
    }
    if (c->session && c->session->bev_client) {
        bufferevent_flush(c->session->bev_client, EV_WRITE, BEV_FLUSH);
        int fd = bufferevent_getfd(c->session->bev_client);
        if (fd >= 0) shutdown(fd, SHUT_WR);
    }
    session_destroy(c->session);
    free(c);
}

static void http_read_cb(struct bufferevent *bev, void *arg) {
    conn_t *c = arg;
    server_ctx_t *srv = c->srv;
    session_t *s = c->session;

    if (!c->http.headers_done) {
        struct evbuffer *in = bufferevent_get_input(bev);
        struct evbuffer_ptr ptr = evbuffer_search(in, "\r\n\r\n", 4, NULL);
        if (ptr.pos < 0) {
            if (evbuffer_get_length(in) > 16384) {
                { const char *r="HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"; int fd=bufferevent_getfd(bev); if(fd>=0){ssize_t _=write(fd,r,strlen(r));(void)_;} }
                http_finish(c, 0);
            }
            return;
        }
        size_t header_len = (size_t)ptr.pos + 4;
        if (header_len > sizeof c->http.reqbuf - 1) header_len = sizeof c->http.reqbuf - 1;
        evbuffer_copyout(in, c->http.reqbuf, header_len);
        c->http.reqbuf[header_len] = '\0';
        c->http.req_len = header_len;
        c->http.headers_done = 1;

        http_request_info_t info;
        if (http_proxy_parse_request(c->http.reqbuf, header_len, &info) != 0) {
            { const char *r="HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"; int fd=bufferevent_getfd(bev); if(fd>=0){ssize_t _=write(fd,r,strlen(r));(void)_;} }
            http_finish(c, 0);
            return;
        }
        session_set_target(s, info.host, info.port);
        session_set_method(s, info.method);
        c->http.is_connect = info.is_connect;
        c->http.info = info;

        /* auth */
        if (srv->config.proxy_auth_enabled) {
            /* need Proxy-Authorization header; parse from reqbuf */
            char *h = strcasestr(c->http.reqbuf, "Proxy-Authorization:");
            char val[256] = {0};
            if (h) {
                h += strlen("Proxy-Authorization:");
                while (*h == ' ') h++;
                size_t i = 0;
                while (h[i] && h[i] != '\r' && h[i] != '\n' && i < sizeof val - 1) { val[i] = h[i]; i++; }
                val[i] = '\0';
            }
            if (!auth_basic_check(val, srv->config.proxy_username, srv->config.proxy_password)) {
                const char *resp = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"rybaproxy\"\r\nConnection: close\r\n\r\n";
                int fd = bufferevent_getfd(bev);
                if (fd >= 0) { ssize_t _ = write(fd, resp, strlen(resp)); (void)_; }
                http_finish(c, 0);
                return;
            }
        }

        /* routing */
        int up_id = router_select(&srv->router, info.host, info.port, PROTO_HTTP, s->client_ip);
        if (up_id < 0) {
            /* default by name */
            upstream_profile_t *def = find_upstream_by_name(srv, srv->config.default_upstream);
            up_id = def ? def->id : 0;
        }
        upstream_profile_t *up = find_upstream_by_id(srv, up_id);
        if (!up) up = find_upstream_by_name(srv, "direct");
        if (!up) { ensure_direct(srv); up = find_upstream_by_name(srv, "direct"); }

        /* connect */
        int fd = -1;
        if (upstream_connect_profile(up, info.host, info.port, &fd) != 0) {
            upstream_profile_t *fallback = NULL;
            if (srv->config.fallback_to_direct && up && up->type != UPSTREAM_DIRECT) {
                fallback = find_upstream_by_name(srv, "direct");
                if (!fallback) { ensure_direct(srv); fallback = find_upstream_by_name(srv, "direct"); }
                if (fallback) upstream_connect_profile(fallback, info.host, info.port, &fd);
                up = fallback ? fallback : up;
            }
        }
        if (fd < 0) {
            { const char *r="HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"; int fd=bufferevent_getfd(bev); if(fd>=0){ssize_t _=write(fd,r,strlen(r));(void)_;} }
            http_finish(c, 0);
            return;
        }
        set_nonblock(fd);
        struct bufferevent *bev_up = bufferevent_socket_new(srv->base, fd, BEV_OPT_CLOSE_ON_FREE);
        s->bev_upstream = bev_up;
        s->upstream_id = up ? up->id : 0;

        struct evbuffer *in2 = bufferevent_get_input(bev);
        struct evbuffer *up_out = bufferevent_get_output(bev_up);
        if (!c->http.is_connect) {
            evbuffer_drain(in2, header_len);
            {
                /* rewrite absolute URI to origin form (tunnel mode) */
                char path[2048];
                snprintf(path, sizeof path, "/");
                const char *u = c->http.info.url;
                if (strncmp(u, "http://", 7) == 0 || strncmp(u, "https://", 8) == 0) {
                    int ssl = (strncmp(u, "https://", 8) == 0);
                    const char *p = u + (ssl ? 8 : 7);
                    const char *slash = strchr(p, '/');
                    if (slash) snprintf(path, sizeof path, "%s", slash);
                    else snprintf(path, sizeof path, "/");
                }
                char *rest = strstr(c->http.reqbuf, "\r\n");
                if (rest) rest += 2;
                char outbuf[16384];
                int on = snprintf(outbuf, sizeof outbuf, "%s %s HTTP/1.1\r\n%s",
                                  c->http.info.method, path, rest ? rest : "");
                bufferevent_write(bev_up, outbuf, on);
            }
            evbuffer_add_buffer(up_out, in2);
        } else {
            evbuffer_drain(in2, header_len);
            evbuffer_add_buffer(up_out, in2);
            { const char *r="HTTP/1.1 200 Connection Established\r\n\r\n"; int fd=bufferevent_getfd(bev); if(fd>=0){ssize_t _=write(fd,r,strlen(r));(void)_;} }
        }

        relay_start(s, bev, bev_up);
    } else {
        /* headers already processed; relay handles future data */
    }
}

static void http_event_cb(struct bufferevent *bev, short events, void *arg) {
    conn_t *c = arg;
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        session_finish(c->session, (events & BEV_EVENT_TIMEOUT) ? SESS_TIMEOUT : SESS_DONE, 0, NULL);
        http_finish(c, 0);
    }
}

/* ---------- SOCKS5 handling ---------- */

static void socks_send(struct bufferevent *bev, const void *d, size_t n) {
    bufferevent_write(bev, d, n);
}

static void socks_read_cb(struct bufferevent *bev, void *arg) {
    conn_t *c = arg;
    server_ctx_t *srv = c->srv;
    session_t *s = c->session;
    struct evbuffer *in = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(in);
    if (len == 0) return;

    unsigned char *data = malloc(len);
    evbuffer_copyout(in, data, len);

    if (c->socks.state == 0) {
        /* handshake: VER NMETHODS METHODS */
        if (len < 2) { free(data); return; }
        int nmethods = data[1];
        if (len < (size_t)(2 + nmethods)) { free(data); return; }
        /* choose method */
        int offer_noauth = 0, offer_auth = 0;
        for (int i = 0; i < nmethods; i++) {
            if (data[2+i] == 0x00) offer_noauth = 1;
            if (data[2+i] == 0x02) offer_auth = 1;
        }
        unsigned char method;
        if (srv->config.proxy_auth_enabled) {
            if (offer_auth) method = 0x02;
            else method = 0xFF;
        } else {
            if (offer_noauth) method = 0x00;
            else method = 0xFF;
        }
        unsigned char resp[2] = {0x05, method};
        socks_send(bev, resp, 2);
        evbuffer_drain(in, 2 + nmethods);
        if (method == 0xFF) {
            free(data);
            http_finish((conn_t*)c, 0); /* reuse finish */
            /* but c is conn_t*; okay */
            return;
        }
        c->socks.state = (method == 0x02) ? 1 : 2;
        free(data);
        /* reprocess */
        socks_read_cb(bev, arg);
        return;
    }

    if (c->socks.state == 1) {
        /* RFC1929 auth: VER ULEN UNAME PLEN PASSWD */
        if (len < 2) { free(data); return; }
        int ulen = data[1];
        if (len < (size_t)(2 + ulen + 1)) { free(data); return; }
        int plen = data[2 + ulen];
        if (len < (size_t)(2 + ulen + 1 + plen)) { free(data); return; }
        char user[128] = {0}, pass[128] = {0};
        if (ulen < 127 && plen < 127) {
            memcpy(user, data + 2, ulen);
            memcpy(pass, data + 3 + ulen, plen);
        }
        int ok = (strcmp(user, srv->config.proxy_username) == 0 &&
                  strcmp(pass, srv->config.proxy_password) == 0);
        unsigned char resp[2] = {0x01, ok ? 0x00 : 0x01};
        socks_send(bev, resp, 2);
        evbuffer_drain(in, 2 + ulen + 1 + plen);
        if (!ok) {
            free(data);
            http_finish((conn_t*)c, 0);
            return;
        }
        c->socks.state = 2;
        free(data);
        socks_read_cb(bev, arg);
        return;
    }

    if (c->socks.state == 2) {
        /* request */
        char host[256] = {0};
        uint16_t port = 0;
        int consumed = socks5_parse_request(data, len, host, sizeof host, &port);
        if (consumed == -1) { free(data); return; } /* incomplete */
        if (consumed < 0) {
            /* unsupported */
            unsigned char r[10];
            socks5_build_reply(r, SOCKS5_REP_CMD_NOT_SUPPORTED);
            socks_send(bev, r, 10);
            free(data);
            http_finish((conn_t*)c, 0);
            return;
        }
        evbuffer_drain(in, (size_t)consumed);

        session_set_target(s, host, port);
        snprintf(s->method, sizeof s->method, "SOCKS5-CONNECT");

        int up_id = router_select(&srv->router, host, port, PROTO_SOCKS5, s->client_ip);
        if (up_id < 0) {
            upstream_profile_t *def = find_upstream_by_name(srv, srv->config.default_upstream);
            up_id = def ? def->id : 0;
        }
        upstream_profile_t *up = find_upstream_by_id(srv, up_id);
        if (!up) { ensure_direct(srv); up = find_upstream_by_name(srv, "direct"); }

        int fd = -1;
        if (upstream_connect_profile(up, host, port, &fd) != 0) {
            if (srv->config.fallback_to_direct && up && up->type != UPSTREAM_DIRECT) {
                upstream_profile_t *fb = find_upstream_by_name(srv, "direct");
                if (!fb) { ensure_direct(srv); fb = find_upstream_by_name(srv, "direct"); }
                if (fb) upstream_connect_profile(fb, host, port, &fd);
                up = fb ? fb : up;
            }
        }
        if (fd < 0) {
            unsigned char r[10];
            socks5_build_reply(r, SOCKS5_REP_FAILURE);
            socks_send(bev, r, 10);
            free(data);
            http_finish((conn_t*)c, 0);
            return;
        }
        set_nonblock(fd);
        struct bufferevent *bev_up = bufferevent_socket_new(srv->base, fd, BEV_OPT_CLOSE_ON_FREE);
        s->bev_upstream = bev_up;
        s->upstream_id = up ? up->id : 0;

        unsigned char r[10];
        socks5_build_reply(r, SOCKS5_REP_SUCCESS);
        socks_send(bev, r, 10);

        relay_start(s, bev, bev_up);
        free(data);
        return;
    }

    free(data);
}

static void socks_event_cb(struct bufferevent *bev, short events, void *arg) {
    conn_t *c = arg;
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        session_finish(c->session, (events & BEV_EVENT_TIMEOUT) ? SESS_TIMEOUT : SESS_DONE, 0, NULL);
        http_finish(c, 0);
    }
}

/* ---------- accept ---------- */

static void accept_cb(struct evconnlistener *lev, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *arg) {
    (void)lev; (void)addr; (void)socklen;
    server_ctx_t *srv = arg;
    set_nonblock(fd);
    char ip[64]; ip[0] = '\0';
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip);
    } else snprintf(ip, sizeof ip, "unknown");

    int is_http = (fd == -1) ? 1 : 1; /* determine by listener? We'll pass via arg? */
    /* We need know which port. Use fd? Instead, store in srv? We'll create two listeners with different callbacks. */
    (void)is_http;
    (void)srv;
    (void)ip;
    (void)fd;
}

/* We'll instead create accept handlers per protocol. */

static void http_accept_cb(struct evconnlistener *lev, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *arg) {
    (void)lev; (void)socklen;
    server_ctx_t *srv = arg;
    set_nonblock(fd);
    char ip[64] = "unknown";
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip);
    }
    session_t *s = session_create(srv->base, PROTO_HTTP, ip);
    conn_t *c = calloc(1, sizeof *c);
    c->srv = srv; c->session = s; c->is_http = 1;
    s->user_data = c;

    struct bufferevent *bev = bufferevent_socket_new(srv->base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, http_read_cb, NULL, http_event_cb, c);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    s->bev_client = bev;
}

static void socks_accept_cb(struct evconnlistener *lev, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *arg) {
    (void)lev; (void)socklen;
    server_ctx_t *srv = arg;
    set_nonblock(fd);
    char ip[64] = "unknown";
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip);
    }
    session_t *s = session_create(srv->base, PROTO_SOCKS5, ip);
    conn_t *c = calloc(1, sizeof *c);
    c->srv = srv; c->session = s; c->is_http = 0;
    s->user_data = c;

    struct bufferevent *bev = bufferevent_socket_new(srv->base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, socks_read_cb, NULL, socks_event_cb, c);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    s->bev_client = bev;
}

int server_init(server_ctx_t *ctx, const config_t *cfg) {
    memset(ctx, 0, sizeof *ctx);
    pthread_mutex_init(&ctx->lock, NULL);
    ctx->config = *cfg;
    ctx->upstreams = cfg->upstreams;
    ctx->upstream_count = cfg->upstream_count;
    ensure_direct(ctx);

    router_init(&ctx->router, ctx->config.default_upstream, ctx->config.fallback_to_direct);

    ctx->base = event_base_new();
    if (!ctx->base) return -1;

    /* listeners */
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons((uint16_t)ctx->config.http_port);

    struct evconnlistener *levh = evconnlistener_new_bind(ctx->base, http_accept_cb, ctx,
        LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
        (struct sockaddr*)&sin, sizeof sin);
    if (!levh) return -1;

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons((uint16_t)ctx->config.socks5_port);
    struct evconnlistener *levs = evconnlistener_new_bind(ctx->base, socks_accept_cb, ctx,
        LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
        (struct sockaddr*)&sin, sizeof sin);
    if (!levs) return -1;

    return 0;
}

int server_run(server_ctx_t *ctx) {
    event_base_dispatch(ctx->base);
    return 0;
}

void server_free(server_ctx_t *ctx) {
    pthread_mutex_destroy(&ctx->lock);
    if (ctx->base) event_base_free(ctx->base);
    router_free(&ctx->router);
    /* do not free upstreams if owned by config? free anyway */
    free(ctx->upstreams);
    ctx->upstreams = NULL;
    ctx->upstream_count = 0;
}

void server_session_closed(session_t *s) {
    if (!s || !s->user_data) return;
    http_finish((conn_t*)s->user_data, 0);
}
