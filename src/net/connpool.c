/* 连接池：把阻塞的「DNS + connect + 上游握手」搬出事件循环。
 *
 * 结构：N 个工作线程从任务队列取活，干完把结果放到完成队列，再往 socketpair
 * 写一个字节唤醒事件循环；事件循环线程只负责在 pump 里回调调用方。
 * 跨线程只共享这两个队列和唤醒 fd，不需要给 event_base 开 evthread。
 */
#include "rybaproxy/connpool.h"
#include "rybaproxy/upstream.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/event.h>

#define CONNPOOL_HARD_MAX 32

typedef struct conn_job {
    struct conn_job *next;
    void *ctx;
    upstream_profile_t up;
    char host[256];
    uint16_t port;
    connpool_done_fn done;
    void *ud;
    int fd;
    int canceled;
} conn_job_t;

static struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    conn_job_t *waiting;   /* 待做 */
    conn_job_t *finished;  /* 做完待回调 */
    pthread_t threads[CONNPOOL_HARD_MAX];
    int workers;
    int running;
    int wake[2];           /* [0] 事件循环读，[1] 工作线程写 */
    struct event *wake_ev;
    struct event_base *base;
    connpool_connect_fn connect_fn;
} g_pool = {
    .mu = PTHREAD_MUTEX_INITIALIZER,
    .cv = PTHREAD_COND_INITIALIZER,
    .wake = {-1, -1},
};

/* ---------- 内部工具 ---------- */

static void job_free(conn_job_t *j) {
    if (!j) return;
    if (j->fd >= 0) close(j->fd);
    free(j);
}

/* 事件循环线程：把完成队列里的活回调掉 */
static void connpool_pump(evutil_socket_t fd, short what, void *arg) {
    (void)what; (void)arg;
    char drain[64];
    while (read(fd, drain, sizeof drain) > 0) { }

    pthread_mutex_lock(&g_pool.mu);
    conn_job_t *list = g_pool.finished;
    g_pool.finished = NULL;
    pthread_mutex_unlock(&g_pool.mu);

    while (list) {
        conn_job_t *j = list;
        list = j->next;
        j->next = NULL;
        if (j->canceled) {
            /* 调用方已经走了：连上的 fd 由这里关掉，绝不回调 */
            job_free(j);
            continue;
        }
        connpool_done_fn done = j->done;
        void *ctx = j->ctx, *ud = j->ud;
        int jfd = j->fd, up_id = j->up.id;
        j->fd = -1;
        free(j);
        done(ctx, jfd, up_id, ud);
    }
}

static void *worker_main(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_pool.mu);
        while (g_pool.running && !g_pool.waiting) pthread_cond_wait(&g_pool.cv, &g_pool.mu);
        if (!g_pool.running) { pthread_mutex_unlock(&g_pool.mu); break; }
        conn_job_t *j = g_pool.waiting;
        g_pool.waiting = j->next;
        j->next = NULL;
        pthread_mutex_unlock(&g_pool.mu);

        int fd = -1;
        connpool_connect_fn fn = g_pool.connect_fn ? g_pool.connect_fn : NULL;
        if (!fn || fn(&j->up, j->host, j->port, &fd) != 0) {
            if (fd >= 0) { close(fd); fd = -1; }
        }
        j->fd = fd;

        pthread_mutex_lock(&g_pool.mu);
        if (j->canceled) {
            job_free(j);
            pthread_mutex_unlock(&g_pool.mu);
            continue;
        }
        j->next = g_pool.finished;
        g_pool.finished = j;
        pthread_mutex_unlock(&g_pool.mu);

        unsigned char one = 1;
        ssize_t n = write(g_pool.wake[1], &one, 1);
        (void)n; /* EAGAIN 说明循环还没处理上一批，已经醒了，不必再唤 */
    }
    return NULL;
}

/* 默认连接实现：direct / HTTP 代理 CONNECT / SOCKS5 */
static int default_connect(const upstream_profile_t *up, const char *host,
                           uint16_t port, int *out_fd) {
    if (!up) return -1;
    if (up->type == UPSTREAM_DIRECT) return upstream_connect_direct(host, port, out_fd);
    if (up->type == UPSTREAM_HTTP) return upstream_connect_http(up, host, port, out_fd);
    if (up->type == UPSTREAM_SOCKS5) return upstream_connect_socks5(up, host, port, out_fd);
    return -1;
}

/* ---------- 对外接口 ---------- */

int connpool_init(struct event_base *base, int workers) {
    if (!base) return -1;
    if (g_pool.running) return 0;
    if (workers <= 0) workers = 8;
    if (workers > CONNPOOL_HARD_MAX) workers = CONNPOOL_HARD_MAX;

    if (!g_pool.connect_fn) g_pool.connect_fn = default_connect;
    g_pool.base = base;
    g_pool.waiting = g_pool.finished = NULL;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool.wake) != 0) return -1;
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(g_pool.wake[i], F_GETFL, 0);
        if (fl >= 0) fcntl(g_pool.wake[i], F_SETFL, fl | O_NONBLOCK);
    }
    g_pool.wake_ev = event_new(base, g_pool.wake[0], EV_READ | EV_PERSIST,
                               connpool_pump, NULL);
    if (!g_pool.wake_ev) return -1;
    if (event_add(g_pool.wake_ev, NULL) != 0) return -1;

    g_pool.running = 1;
    for (int i = 0; i < workers; i++) {
        if (pthread_create(&g_pool.threads[i], NULL, worker_main, NULL) != 0) break;
        g_pool.workers++;
    }
    if (g_pool.workers == 0) { connpool_shutdown(); return -1; }
    return 0;
}

void connpool_shutdown(void) {
    if (!g_pool.running) return;
    pthread_mutex_lock(&g_pool.mu);
    g_pool.running = 0;
    pthread_cond_broadcast(&g_pool.cv);
    pthread_mutex_unlock(&g_pool.mu);
    for (int i = 0; i < g_pool.workers; i++) pthread_join(g_pool.threads[i], NULL);
    g_pool.workers = 0;

    /* 队列里剩下的任务：能关的关，能回调的丢弃（进程要退了） */
    pthread_mutex_lock(&g_pool.mu);
    conn_job_t *l = g_pool.waiting;
    g_pool.waiting = NULL;
    conn_job_t *f = g_pool.finished;
    g_pool.finished = NULL;
    pthread_mutex_unlock(&g_pool.mu);
    while (l) { conn_job_t *n = l->next; job_free(l); l = n; }
    while (f) { conn_job_t *n = f->next; job_free(f); f = n; }

    if (g_pool.wake_ev) { event_free(g_pool.wake_ev); g_pool.wake_ev = NULL; }
    if (g_pool.wake[0] >= 0) { close(g_pool.wake[0]); g_pool.wake[0] = -1; }
    if (g_pool.wake[1] >= 0) { close(g_pool.wake[1]); g_pool.wake[1] = -1; }
    g_pool.base = NULL;
}

void connpool_set_connect_fn(connpool_connect_fn fn) { g_pool.connect_fn = fn; }

int connpool_submit(void *ctx, const upstream_profile_t *up, const char *host,
                    uint16_t port, connpool_done_fn done, void *ud) {
    if (!ctx || !up || !host || !host[0] || !done) return -1;
    if (!g_pool.running) return -1;

    conn_job_t *j = calloc(1, sizeof *j);
    if (!j) return -1;
    j->ctx = ctx;
    j->up = *up;
    snprintf(j->host, sizeof j->host, "%s", host);
    j->port = port;
    j->done = done;
    j->ud = ud;
    j->fd = -1;

    pthread_mutex_lock(&g_pool.mu);
    j->next = g_pool.waiting;
    g_pool.waiting = j;
    pthread_cond_signal(&g_pool.cv);
    pthread_mutex_unlock(&g_pool.mu);
    return 0;
}

void connpool_cancel(void *ctx) {
    if (!ctx) return;
    pthread_mutex_lock(&g_pool.mu);
    /* 未开工的：标记后由工人线程负责关闭并释放 */
    for (conn_job_t *j = g_pool.waiting; j; j = j->next)
        if (j->ctx == ctx) j->canceled = 1;
    /* 已完成待回调的：标记后由 pump 负责关闭并释放 */
    for (conn_job_t *j = g_pool.finished; j; j = j->next)
        if (j->ctx == ctx) j->canceled = 1;
    pthread_mutex_unlock(&g_pool.mu);
}
