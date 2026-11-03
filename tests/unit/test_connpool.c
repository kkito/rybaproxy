#include <cmocka.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <event2/event.h>

#include "rybaproxy/connpool.h"

/* 异步连接池单测：全部走本地 socketpair / 假连接函数，零网络。 */

static struct event_base *g_base;

static int setup(void **s) {
    (void)s;
    g_base = event_base_new();
    assert_non_null(g_base);
    return 0;
}

static int teardown(void **s) {
    (void)s;
    connpool_shutdown();
    if (g_base) { event_base_free(g_base); g_base = NULL; }
    return 0;
}

/* ---------- 假连接函数（注入，不碰真实网络） ---------- */
static int fake_connect_delay(const upstream_profile_t *up, const char *host,
                              uint16_t port, int *out_fd) {
    (void)up; (void)host; (void)port;
    usleep(300 * 1000); /* 模拟一次慢连接：300ms */
    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    *out_fd = sv[0];
    close(sv[1]);
    return 0;
}

static int fake_connect_fail(const upstream_profile_t *up, const char *host,
                             uint16_t port, int *out_fd) {
    (void)up; (void)host; (void)port; (void)out_fd;
    usleep(50 * 1000);
    return -1;
}

/* 返回 socketpair 的一端，另一端留在 g_peer，供测试观察是否被关掉 */
static int g_peer = -1;
static int fake_connect_pair(const upstream_profile_t *up, const char *host,
                             uint16_t port, int *out_fd) {
    (void)up; (void)host; (void)port;
    usleep(100 * 1000);
    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    *out_fd = sv[0];
    g_peer = sv[1];
    return 0;
}

/* ---------- 探针 ---------- */
typedef struct {
    struct event_base *base;
    int ticks;
    int done_calls;
    int done_fd;
    int done_up_id;
} probe_t;

static void tick_cb(evutil_socket_t fd, short ev, void *arg) {
    (void)fd; (void)ev;
    ((probe_t *)arg)->ticks++;
}

static void done_cb(void *ctx, int fd, int upstream_id, void *ud) {
    (void)ctx;
    probe_t *p = ud;
    p->done_calls++;
    p->done_fd = fd;
    p->done_up_id = upstream_id;
    event_base_loopexit(p->base, NULL);
}

static void run_loop(probe_t *p, int ms) {
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    event_base_loopexit(p->base, &tv);
    event_base_dispatch(p->base);
}

/* ---------- 用例 ---------- */

/* RED：连接必须在工作线程里做，事件循环不能被它阻塞。
 * 假连接耗时 300ms；期间 20ms 一次的定时器必须照常跑够多次。 */
static void test_pool_does_not_block_loop(void **s) {
    (void)s;
    connpool_set_connect_fn(fake_connect_delay);
    assert_int_equal(connpool_init(g_base, 2), 0);

    probe_t p;
    memset(&p, 0, sizeof p);
    p.base = g_base;
    p.done_fd = -2;

    struct timeval tv = {0, 20 * 1000};
    struct event *tick = event_new(g_base, -1, EV_PERSIST, tick_cb, &p);
    assert_non_null(tick);
    event_add(tick, &tv);

    upstream_profile_t up;
    memset(&up, 0, sizeof up);
    up.id = 7;
    up.type = UPSTREAM_DIRECT;

    assert_int_equal(connpool_submit(&p, &up, "slow.example", 443, done_cb, &p), 0);
    run_loop(&p, 3000);

    event_free(tick);
    assert_int_equal(p.done_calls, 1);
    assert_true(p.done_fd >= 0);
    assert_int_equal(p.done_up_id, 7);
    /* 300ms 里至少要有 5 个 20ms 的 tick —— 说明循环没被连接卡住 */
    assert_true(p.ticks >= 5);
    close(p.done_fd);
}

/* 连接失败：回调拿到的 fd 是负数，不许崩 */
static void test_failed_connect_reports_negative_fd(void **s) {
    (void)s;
    connpool_set_connect_fn(fake_connect_fail);
    assert_int_equal(connpool_init(g_base, 1), 0);

    probe_t p;
    memset(&p, 0, sizeof p);
    p.base = g_base;
    p.done_fd = -2;

    upstream_profile_t up;
    memset(&up, 0, sizeof up);
    up.id = 3;
    up.type = UPSTREAM_HTTP;

    assert_int_equal(connpool_submit(&p, &up, "dead.example", 80, done_cb, &p), 0);
    run_loop(&p, 3000);
    assert_int_equal(p.done_calls, 1);
    assert_int_equal(p.done_fd, -1);
    assert_int_equal(p.done_up_id, 3);
}

/* 取消：客户端先断了，池子必须把已经连上的 fd 关掉，且不再回调 */
static void test_cancel_closes_fd_and_skips_callback(void **s) {
    (void)s;
    g_peer = -1;
    connpool_set_connect_fn(fake_connect_pair);
    assert_int_equal(connpool_init(g_base, 1), 0);

    probe_t p;
    memset(&p, 0, sizeof p);
    p.base = g_base;

    upstream_profile_t up;
    memset(&up, 0, sizeof up);
    up.id = 1;
    up.type = UPSTREAM_DIRECT;

    assert_int_equal(connpool_submit(&p, &up, "cancel.example", 443, done_cb, &p), 0);
    connpool_cancel(&p); /* 连接还在飞（假连接睡 100ms） */
    run_loop(&p, 1000);

    assert_int_equal(p.done_calls, 0);
    assert_true(g_peer >= 0);
    /* 对端被关掉 → read 返回 0（EOF），不是 -1 */
    char buf[8];
    assert_int_equal((int)read(g_peer, buf, sizeof buf), 0);
    close(g_peer);
    g_peer = -1;
}

static void test_submit_rejects_bad_args(void **s) {
    (void)s;
    assert_int_equal(connpool_init(g_base, 1), 0);
    upstream_profile_t up;
    memset(&up, 0, sizeof up);
    assert_int_equal(connpool_submit(NULL, &up, "h", 80, done_cb, NULL), -1);
    assert_int_equal(connpool_submit(&up, NULL, "h", 80, done_cb, NULL), -1);
    assert_int_equal(connpool_submit(&up, &up, NULL, 80, done_cb, NULL), -1);
    assert_int_equal(connpool_submit(&up, &up, "", 80, done_cb, NULL), -1);
    assert_int_equal(connpool_submit(&up, &up, "h", 80, NULL, NULL), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_pool_does_not_block_loop, setup, teardown),
        cmocka_unit_test_setup_teardown(test_failed_connect_reports_negative_fd, setup, teardown),
        cmocka_unit_test_setup_teardown(test_cancel_closes_fd_and_skips_callback, setup, teardown),
        cmocka_unit_test_setup_teardown(test_submit_rejects_bad_args, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
