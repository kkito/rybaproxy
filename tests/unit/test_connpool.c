#include <cmocka.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <event2/event.h>

#include "rybaproxy/connpool.h"

/* 连接池单测：全部走 socketpair / 假任务，零网络。 */

static struct event_base *g_base;
static pthread_t g_loop_thread;

static int setup(void **s) {
    (void)s;
    g_base = event_base_new();
    assert_non_null(g_base);
    g_loop_thread = pthread_self();
    return 0;
}

static int teardown(void **s) {
    (void)s;
    connpool_shutdown();
    if (g_base) { event_base_free(g_base); g_base = NULL; }
    return 0;
}

/* ---------- 探针任务 ---------- */
typedef struct {
    int sleep_ms;
    int fail;
    int *peer;
    int ran_off_loop; /* 是否跑在别的线程 */
} task_t;

static int fake_task(void *arg, int *out_fd) {
    task_t *t = arg;
    t->ran_off_loop = !pthread_equal(pthread_self(), g_loop_thread);
    if (t->sleep_ms > 0) usleep((useconds_t)t->sleep_ms * 1000);
    if (t->fail) return -1;
    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    *out_fd = sv[0];
    if (t->peer) *t->peer = sv[1];
    else close(sv[1]);
    return 0;
}

typedef struct {
    struct event_base *base;
    int ticks;
    int done_calls;
    int done_fd;
} probe_t;

static void tick_cb(evutil_socket_t fd, short ev, void *arg) {
    (void)fd; (void)ev;
    ((probe_t *)arg)->ticks++;
}

static void done_cb(void *ctx, int fd, void *ud) {
    (void)ctx;
    probe_t *p = ud;
    p->done_calls++;
    p->done_fd = fd;
    event_base_loopexit(p->base, NULL);
}

static void run_loop(probe_t *p, int ms) {
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    event_base_loopexit(p->base, &tv);
    event_base_dispatch(p->base);
}

/* ---------- 用例 ---------- */

/* RED：任务（含 DNS/connect/握手的阻塞活）必须在工作线程里跑，
 * 事件循环不能被它阻塞 —— 300ms 假任务期间 20ms 的定时器要照常跑够多次。 */
static void test_task_runs_off_loop_and_loop_stays_free(void **s) {
    (void)s;
    assert_int_equal(connpool_init(g_base, 2), 0);

    probe_t p;
    memset(&p, 0, sizeof p);
    p.base = g_base;
    p.done_fd = -2;

    struct timeval tv = {0, 20 * 1000};
    struct event *tick = event_new(g_base, -1, EV_PERSIST, tick_cb, &p);
    event_add(tick, &tv);

    task_t t;
    memset(&t, 0, sizeof t);
    t.sleep_ms = 300;

    assert_int_equal(connpool_submit(&p, fake_task, &t, done_cb, &p), 0);
    run_loop(&p, 3000);
    event_free(tick);

    assert_int_equal(p.done_calls, 1);
    assert_true(p.done_fd >= 0);
    assert_true(t.ran_off_loop);   /* 关键：不许在事件循环线程里做阻塞活 */
    assert_true(p.ticks >= 5);
    close(p.done_fd);
}

static void test_failed_task_reports_negative_fd(void **s) {
    (void)s;
    assert_int_equal(connpool_init(g_base, 1), 0);
    probe_t p;
    memset(&p, 0, sizeof p);
    p.base = g_base;
    p.done_fd = -2;

    task_t t;
    memset(&t, 0, sizeof t);
    t.fail = 1;

    assert_int_equal(connpool_submit(&p, fake_task, &t, done_cb, &p), 0);
    run_loop(&p, 3000);
    assert_int_equal(p.done_calls, 1);
    assert_int_equal(p.done_fd, -1);
}

/* 取消：客户端先断了，池子必须关掉已经拿到的 fd，且不再回调 */
static void test_cancel_closes_fd_and_skips_callback(void **s) {
    (void)s;
    assert_int_equal(connpool_init(g_base, 1), 0);
    probe_t p;
    memset(&p, 0, sizeof p);
    p.base = g_base;

    int peer = -1;
    task_t t;
    memset(&t, 0, sizeof t);
    t.sleep_ms = 100;
    t.peer = &peer;

    assert_int_equal(connpool_submit(&p, fake_task, &t, done_cb, &p), 0);
    connpool_cancel(&p);
    run_loop(&p, 1500);

    assert_int_equal(p.done_calls, 0);
    assert_true(peer >= 0);
    char buf[8];
    assert_int_equal((int)read(peer, buf, sizeof buf), 0); /* EOF：对端被关 */
    close(peer);
}

static void test_submit_rejects_bad_args(void **s) {
    (void)s;
    assert_int_equal(connpool_init(g_base, 1), 0);
    task_t t;
    memset(&t, 0, sizeof t);
    assert_int_equal(connpool_submit(NULL, fake_task, &t, done_cb, NULL), -1);
    assert_int_equal(connpool_submit(&t, NULL, &t, done_cb, NULL), -1);
    assert_int_equal(connpool_submit(&t, fake_task, &t, NULL, NULL), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_task_runs_off_loop_and_loop_stays_free, setup, teardown),
        cmocka_unit_test_setup_teardown(test_failed_task_reports_negative_fd, setup, teardown),
        cmocka_unit_test_setup_teardown(test_cancel_closes_fd_and_skips_callback, setup, teardown),
        cmocka_unit_test_setup_teardown(test_submit_rejects_bad_args, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
