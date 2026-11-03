#include "rybaproxy/server.h"
#include "rybaproxy/strutil.h"

#include "rybaproxy/auth.h"
#include "rybaproxy/config.h"
#include "rybaproxy/connpool.h"
#include "rybaproxy/http_proxy.h"
#include "rybaproxy/log.h"
#include "rybaproxy/relay.h"
#include "rybaproxy/reqlog.h"
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
#include <time.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/util.h>

/* 工作线程数：慢连接最多占满这些线程，再多就排队。
 * 32 足够覆盖家用并发，同时保证黑洞连接不会耗尽。 */
#define CONNPOOL_WORKERS 32

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
    /* 异步连接状态：期间事件循环不被阻塞，客户端断开则取消任务 */
    int connecting;
    int fallback_tried;
    upstream_profile_t up; /* 本次尝试的上游副本（配置数组可能被 web 线程改写） */
    char target_host[256];
    uint16_t target_port;
    long conn_start_ms;
} conn_t;

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
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

/* 薄胶水：direct 上游，没有就补建（原来三处重复） */
static upstream_profile_t *direct_upstream(server_ctx_t *srv) {
    upstream_profile_t *d = find_upstream_by_name(srv, "direct");
    if (!d) { ensure_direct(srv); d = find_upstream_by_name(srv, "direct"); }
    return d;
}

/* 薄胶水：路由选择 + 上游落地 + 打一条决策日志。
 * 判定全在纯函数 router_select_ex / upstream_pick 里，这里只做副作用。 */
static upstream_profile_t *pick_upstream_logged(conn_t *c, const char *host, uint16_t port,
                                                protocol_t proto) {
    server_ctx_t *srv = c->srv;
    router_match_t m;
    int route_id = router_select_ex(&srv->router, host, port, proto, c->session->client_ip, &m);
    int idx = upstream_pick(srv->upstreams, srv->upstream_count,
                            srv->config.default_upstream, route_id);
    if (idx < 0) {
        ensure_direct(srv);
        idx = upstream_pick(srv->upstreams, srv->upstream_count,
                            srv->config.default_upstream, route_id);
    }
    upstream_profile_t *up = idx < 0 ? NULL : &srv->upstreams[idx];

    /* 决策日志：以后翻日志能直接看出「这个域名为什么走了这条线」 */
    reqlog_route_t r;
    memset(&r, 0, sizeof r);
    r.id = c->session->id;
    r.client = c->session->client_ip;
    r.host = host;
    r.port = port;
    r.proto = (proto == PROTO_SOCKS5) ? "SOCKS5" : "HTTP";
    r.method = c->session->method[0] ? c->session->method : NULL;
    r.rule_id = m.rule_id;
    r.rule_name = m.rule_name;
    r.upstream = up ? up->name : "(none)";
    r.geo_site = m.geo_site;
    r.geo_host = m.geo_host;
    r.geo_lan = m.geo_lan;
    char line[512];
    reqlog_format_route(line, sizeof line, &r);
    LOG_INFO("%s", line);
    return up;
}

/* ---------- 连接上游（异步，跑在 connpool 的线程里） ---------- */

static void http_upstream_ready(conn_t *c, int fd);
static void socks_upstream_ready(conn_t *c, int fd);
static void http_respond_error(conn_t *c, int status, const char *reason);
static void socks_respond_failure(conn_t *c);

static void on_upstream_ready(void *ctx, int fd, int upstream_id, void *ud);

static void begin_connect(conn_t *c, upstream_profile_t *up) {
    c->up = *up;
    c->session->upstream_id = up->id;
    c->connecting = 1;
    c->conn_start_ms = now_ms();
    if (connpool_submit(c, &c->up, c->target_host, c->target_port,
                        on_upstream_ready, c) != 0) {
        c->connecting = 0;
        if (c->is_http) http_respond_error(c, 502, "pool_unavailable");
        else socks_respond_failure(c);
        return;
    }
}

static void on_upstream_ready(void *ctx, int fd, int upstream_id, void *ud) {
    (void)ud;
    conn_t *c = ctx;
    server_ctx_t *srv = c->srv;
    c->connecting = 0;
    long ms = now_ms() - c->conn_start_ms;

    char line[256];
    reqlog_format_connect(line, sizeof line, c->session->id, c->up.name, fd >= 0, ms,
                          fd >= 0 ? NULL : (ms >= srv->config.connect_timeout_sec * 1000L
                                            ? "timeout" : "connect_failed"));
    LOG_DEBUG("%s", line);

    if (fd < 0) {
        if (srv->config.fallback_to_direct && c->up.type != UPSTREAM_DIRECT && !c->fallback_tried) {
            upstream_profile_t *fb = direct_upstream(srv);
            if (fb) {
                c->fallback_tried = 1;
                LOG_WARN("[%llu] 上游 %s 连接失败，回落 direct 重试",
                         (unsigned long long)c->session->id, c->up.name);
                begin_connect(c, fb);
                return;
            }
        }
        if (c->is_http) http_respond_error(c, 502, "connect_failed");
        else socks_respond_failure(c);
        return;
    }
    if (upstream_id != c->up.id) c->session->upstream_id = upstream_id;
    set_nonblock(fd);
    if (c->is_http) http_upstream_ready(c, fd);
    else socks_upstream_ready(c, fd);
}

/* 客户端在上游连接期间就断了：取消任务（池子会关掉已连上的 fd） */
static void cancel_pending_connect(conn_t *c) {
    if (c->connecting) {
        connpool_cancel(c);
        c->connecting = 0;
    }
}

/* ---------- 会话收尾 ---------- */

static void log_session_result(session_t *s) {
    if (!s) return;
    const char *err = NULL;
    if (s->status == SESS_TIMEOUT) err = "timeout";
    else if (s->status == SESS_ERROR) err = s->error_msg[0] ? s->error_msg : "error";
    long dur = 0;
    if (s->ended_at > 0 && s->started_at > 0)
        dur = (long)(s->ended_at - s->started_at) * 1000L;
    char line[512];
    reqlog_format_finish(line, sizeof line, s->id, s->target_host, s->target_port,
                         s->error_code, dur, s->bytes_up, s->bytes_down, err);
    LOG_INFO("%s", line);
}

static void http_finish(conn_t *c, int status) {
    cancel_pending_connect(c);
    /* status 是本次响应码：错误路径（400/407/431/502）走到这里时会话还 ACTIVE，
     * 必须先结算再落库，否则 DB 里就是永远"活跃"、error_code=0 的幽灵会话。 */
    if (c->session) session_settle_http(c->session, status);
    if (c->session) {
        log_session_result(c->session);
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

/* 错误响应统一出口：写响应 + 落日志 + 结算（原来 5 处重复） */
static void http_respond_error(conn_t *c, int status, const char *reason) {
    static const struct { int code; const char *resp; } kResponses[] = {
        { 400, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n" },
        { 407, "HTTP/1.1 407 Proxy Authentication Required\r\n"
               "Proxy-Authenticate: Basic realm=\"rybaproxy\"\r\nConnection: close\r\n\r\n" },
        { 431, "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n" },
        { 502, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n" },
    };
    if (c->session)
        LOG_WARN("[%llu] 失败 host=%s:%u upstream=%s reason=%s -> %d",
                 (unsigned long long)c->session->id, c->session->target_host,
                 (unsigned)c->session->target_port, c->up.name[0] ? c->up.name : "-",
                 reason ? reason : "-", status);
    const char *resp = NULL;
    for (size_t i = 0; i < sizeof kResponses / sizeof kResponses[0]; i++)
        if (kResponses[i].code == status) resp = kResponses[i].resp;
    if (!resp) resp = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
    if (c->session && c->session->bev_client) {
        int fd = bufferevent_getfd(c->session->bev_client);
        if (fd >= 0) {
            ssize_t n = write(fd, resp, strlen(resp));
            (void)n;
        }
    }
    http_finish(c, status);
}

/* 空闲超时：以前没有，断掉的会话会永远停在 ACTIVE（DB 里的幽灵会话） */
static void apply_idle_timeout(conn_t *c, struct bufferevent *bev) {
    int sec = c->srv->config.idle_timeout_sec;
    if (sec <= 0) return;
    struct timeval tv = { sec, 0 };
    bufferevent_set_timeouts(bev, &tv, &tv);
}

/* ---------- HTTP handling ---------- */

/* 把客户端的请求行改成 origin-form 后再发给上游 */
static void send_rewritten_request(conn_t *c, struct bufferevent *bev_up) {
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
    if (on > 0) bufferevent_write(bev_up, outbuf, (size_t)on);
}

static void http_upstream_ready(conn_t *c, int fd) {
    server_ctx_t *srv = c->srv;
    struct bufferevent *bev = c->session->bev_client;
    struct bufferevent *bev_up = bufferevent_socket_new(srv->base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev_up) {
        close(fd);
        http_respond_error(c, 502, "bufferevent_failed");
        return;
    }
    c->session->bev_upstream = bev_up;
    apply_idle_timeout(c, bev_up);
    apply_idle_timeout(c, bev);

    struct evbuffer *in2 = bufferevent_get_input(bev);
    struct evbuffer *up_out = bufferevent_get_output(bev_up);
    evbuffer_drain(in2, c->http.req_len);
    if (!c->http.is_connect) {
        send_rewritten_request(c, bev_up);
        evbuffer_add_buffer(up_out, in2);
    } else {
        evbuffer_add_buffer(up_out, in2);
        static const char kEstablished[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
        int cfd = bufferevent_getfd(bev);
        if (cfd >= 0) {
            ssize_t n = write(cfd, kEstablished, sizeof kEstablished - 1);
            (void)n;
        }
    }
    relay_start(c->session, bev, bev_up);
}

static void http_read_cb(struct bufferevent *bev, void *arg) {
    conn_t *c = arg;
    server_ctx_t *srv = c->srv;
    session_t *s = c->session;

    if (c->http.headers_done) return;

    struct evbuffer *in = bufferevent_get_input(bev);
    struct evbuffer_ptr ptr = evbuffer_search(in, "\r\n\r\n", 4, NULL);
    if (ptr.pos < 0) {
        if (evbuffer_get_length(in) > 16384) http_respond_error(c, 431, "header_too_large");
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
        http_respond_error(c, 400, "bad_request");
        return;
    }
    session_set_target(s, info.host, info.port);
    session_set_method(s, info.method);
    c->http.is_connect = info.is_connect;
    c->http.info = info;

    if (srv->config.proxy_auth_enabled) {
        const char *h = str_case_find(c->http.reqbuf, "Proxy-Authorization:");
        char val[256] = {0};
        if (h) {
            h += strlen("Proxy-Authorization:");
            while (*h == ' ') h++;
            size_t i = 0;
            while (h[i] && h[i] != '\r' && h[i] != '\n' && i < sizeof val - 1) { val[i] = h[i]; i++; }
            val[i] = '\0';
        }
        if (!auth_basic_check(val, srv->config.proxy_username, srv->config.proxy_password)) {
            http_respond_error(c, 407, "proxy_auth_required");
            return;
        }
    }

    upstream_profile_t *up = pick_upstream_logged(c, info.host, info.port, PROTO_HTTP);
    if (!up) {
        http_respond_error(c, 502, "no_upstream");
        return;
    }
    snprintf(c->target_host, sizeof c->target_host, "%s", info.host);
    c->target_port = info.port;
    /* 连上游期间不读客户端：数据留在内核缓冲，形成天然背压 */
    bufferevent_disable(bev, EV_READ);
    begin_connect(c, up);
}

static void http_event_cb(struct bufferevent *bev, short events, void *arg) {
    (void)bev;
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

static void socks_respond_failure(conn_t *c) {
    unsigned char r[10];
    socks5_build_reply(r, SOCKS5_REP_FAILURE);
    if (c->session && c->session->bev_client) socks_send(c->session->bev_client, r, 10);
    if (c->session)
        LOG_WARN("[%llu] 失败 host=%s:%u upstream=%s reason=socks5_upstream_failed",
                 (unsigned long long)c->session->id, c->session->target_host,
                 (unsigned)c->session->target_port, c->up.name[0] ? c->up.name : "-");
    http_finish(c, 0);
}

static void socks_upstream_ready(conn_t *c, int fd) {
    server_ctx_t *srv = c->srv;
    struct bufferevent *bev = c->session->bev_client;
    struct bufferevent *bev_up = bufferevent_socket_new(srv->base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev_up) {
        close(fd);
        socks_respond_failure(c);
        return;
    }
    c->session->bev_upstream = bev_up;
    apply_idle_timeout(c, bev_up);
    apply_idle_timeout(c, bev);

    unsigned char r[10];
    socks5_build_reply(r, SOCKS5_REP_SUCCESS);
    socks_send(bev, r, 10);

    struct evbuffer *in2 = bufferevent_get_input(bev);
    struct evbuffer *up_out = bufferevent_get_output(bev_up);
    evbuffer_add_buffer(up_out, in2);
    relay_start(c->session, bev, bev_up);
}

static void socks_read_cb(struct bufferevent *bev, void *arg) {
    conn_t *c = arg;
    server_ctx_t *srv = c->srv;
    session_t *s = c->session;
    struct evbuffer *in = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(in);
    if (len == 0) return;

    unsigned char *data = malloc(len);
    if (!data) return;
    evbuffer_copyout(in, data, len);

    if (c->socks.state == 0) {
        /* handshake: VER NMETHODS METHODS */
        if (len < 2) { free(data); return; }
        int nmethods = data[1];
        if (len < (size_t)(2 + nmethods)) { free(data); return; }
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
        evbuffer_drain(in, 2 + (size_t)nmethods);
        if (method == 0xFF) {
            free(data);
            http_finish(c, 0);
            return;
        }
        c->socks.state = (method == 0x02) ? 1 : 2;
        free(data);
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
            memcpy(user, data + 2, (size_t)ulen);
            memcpy(pass, data + 3 + ulen, (size_t)plen);
        }
        int ok = (strcmp(user, srv->config.proxy_username) == 0 &&
                  strcmp(pass, srv->config.proxy_password) == 0);
        unsigned char resp[2] = {0x01, ok ? 0x00 : 0x01};
        socks_send(bev, resp, 2);
        evbuffer_drain(in, (size_t)(2 + ulen + 1 + plen));
        if (!ok) {
            free(data);
            http_finish(c, 0);
            return;
        }
        c->socks.state = 2;
        free(data);
        socks_read_cb(bev, arg);
        return;
    }

    if (c->socks.state == 2) {
        char host[256] = {0};
        uint16_t port = 0;
        int consumed = socks5_parse_request((const char*)data, len, host, sizeof host, &port);
        if (consumed == -1) { free(data); return; } /* incomplete */
        if (consumed < 0) {
            unsigned char r[10];
            socks5_build_reply(r, SOCKS5_REP_CMD_NOT_SUPPORTED);
            socks_send(bev, r, 10);
            free(data);
            http_finish(c, 0);
            return;
        }
        evbuffer_drain(in, (size_t)consumed);

        session_set_target(s, host, port);
        snprintf(s->method, sizeof s->method, "SOCKS5-CONNECT");

        upstream_profile_t *up = pick_upstream_logged(c, host, port, PROTO_SOCKS5);
        if (!up) {
            free(data);
            socks_respond_failure(c);
            return;
        }
        snprintf(c->target_host, sizeof c->target_host, "%s", host);
        c->target_port = port;
        bufferevent_disable(bev, EV_READ);
        free(data);
        begin_connect(c, up);
        return;
    }

    free(data);
}

static void socks_event_cb(struct bufferevent *bev, short events, void *arg) {
    (void)bev;
    conn_t *c = arg;
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        session_finish(c->session, (events & BEV_EVENT_TIMEOUT) ? SESS_TIMEOUT : SESS_DONE, 0, NULL);
        http_finish(c, 0);
    }
}

/* ---------- accept ---------- */

static void fill_client_ip(struct sockaddr *addr, char *ip, size_t sz) {
    ip[0] = '\0';
    if (!addr) { snprintf(ip, sz, "unknown"); return; }
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip, sz);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sz);
    } else snprintf(ip, sz, "unknown");
}

static void http_accept_cb(struct evconnlistener *lev, evutil_socket_t fd, struct sockaddr *addr,
                           int socklen, void *arg) {
    (void)lev; (void)socklen;
    server_ctx_t *srv = arg;
    set_nonblock(fd);
    char ip[64];
    fill_client_ip(addr, ip, sizeof ip);
    session_t *s = session_create(srv->base, PROTO_HTTP, ip);
    conn_t *c = calloc(1, sizeof *c);
    if (!s || !c) { if (s) session_destroy(s); free(c); close(fd); return; }
    c->srv = srv; c->session = s; c->is_http = 1;
    s->user_data = c;

    struct bufferevent *bev = bufferevent_socket_new(srv->base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) { session_destroy(s); free(c); close(fd); return; }
    bufferevent_setcb(bev, http_read_cb, NULL, http_event_cb, c);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    s->bev_client = bev;
}

static void socks_accept_cb(struct evconnlistener *lev, evutil_socket_t fd, struct sockaddr *addr,
                            int socklen, void *arg) {
    (void)lev; (void)socklen;
    server_ctx_t *srv = arg;
    set_nonblock(fd);
    char ip[64];
    fill_client_ip(addr, ip, sizeof ip);
    session_t *s = session_create(srv->base, PROTO_SOCKS5, ip);
    conn_t *c = calloc(1, sizeof *c);
    if (!s || !c) { if (s) session_destroy(s); free(c); close(fd); return; }
    c->srv = srv; c->session = s; c->is_http = 0;
    s->user_data = c;

    struct bufferevent *bev = bufferevent_socket_new(srv->base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) { session_destroy(s); free(c); close(fd); return; }
    bufferevent_setcb(bev, socks_read_cb, NULL, socks_event_cb, c);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    s->bev_client = bev;
}

int server_init(server_ctx_t *ctx, const config_t *cfg) {
    memset(ctx, 0, sizeof *ctx);
    pthread_mutex_init(&ctx->lock, NULL);
    ctx->config = *cfg;
    ctx->config.upstreams = NULL;
    ctx->config.upstream_count = 0;
    /* deep copy: ctx owns its array, config keeps its own (no double free) */
    if (cfg->upstream_count > 0 && cfg->upstreams) {
        ctx->upstreams = calloc((size_t)cfg->upstream_count, sizeof(upstream_profile_t));
        if (ctx->upstreams) {
            memcpy(ctx->upstreams, cfg->upstreams,
                   (size_t)cfg->upstream_count * sizeof(upstream_profile_t));
            ctx->upstream_count = cfg->upstream_count;
        }
    }
    ensure_direct(ctx);

    router_init(&ctx->router, ctx->config.default_upstream, ctx->config.fallback_to_direct);
    /* rules 持久化：DB 有则加载（含 geo 条件），否则保持空路由 */
    extern int web_rules_db_load_all(router_t *r);
    web_rules_db_load_all(&ctx->router);

    ctx->base = event_base_new();
    if (!ctx->base) return -1;

    /* 阻塞式上游连接交给线程池；事件循环只收结果 */
    if (connpool_init(ctx->base, CONNPOOL_WORKERS) != 0) return -1;

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
    connpool_shutdown();
    pthread_mutex_destroy(&ctx->lock);
    if (ctx->base) event_base_free(ctx->base);
    router_free(&ctx->router);
    free(ctx->upstreams);
    ctx->upstreams = NULL;
    ctx->upstream_count = 0;
}

void server_session_closed(session_t *s) {
    if (!s || !s->user_data) return;
    http_finish((conn_t*)s->user_data, 0);
}
