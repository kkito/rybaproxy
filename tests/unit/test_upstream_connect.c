#include <cmocka.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

#include "rybaproxy/upstream.h"

/* 上游连接/握手的单测：只用 127.0.0.1 的本地监听，零外网。 */

static int listen_local(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(fd >= 0);
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;
    assert_int_equal(bind(fd, (struct sockaddr*)&sin, sizeof sin), 0);
    assert_int_equal(listen(fd, 16), 0);
    socklen_t sl = sizeof sin;
    assert_int_equal(getsockname(fd, (struct sockaddr*)&sin, &sl), 0);
    *port = ntohs(sin.sin_port);
    return fd;
}

static long elapsed_ms(const struct timespec *a, const struct timespec *b) {
    return (b->tv_sec - a->tv_sec) * 1000L + (b->tv_nsec - a->tv_nsec) / 1000000L;
}

/* RED：上游接了 TCP 却永远不回 CONNECT 应答时，握手必须超时失败，
 * 不能永久挂住（旧实现 recv 没有超时，工作线程会被永久占死）。 */
static void test_http_handshake_times_out(void **s) {
    (void)s;
    uint16_t port = 0;
    int lfd = listen_local(&port);
    upstream_set_connect_timeout(1);

    upstream_profile_t up;
    memset(&up, 0, sizeof up);
    up.id = 1;
    up.type = UPSTREAM_HTTP;
    snprintf(up.name, sizeof up.name, "silent");
    snprintf(up.host, sizeof up.host, "127.0.0.1");
    up.port = port;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int fd = -1;
    int rc = upstream_connect_http(&up, "example.test", 443, &fd);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = elapsed_ms(&t0, &t1);

    assert_int_equal(rc, -1);
    assert_true(fd < 0);
    assert_true(ms >= 900);   /* 真的在等超时，不是立刻报错 */
    assert_true(ms < 5000);   /* 也不会无限等 */
    close(lfd);
}

/* 上游连不上（端口没人听）时，必须快速失败而不是挂住 */
static void test_http_refused_fails_fast(void **s) {
    (void)s;
    uint16_t port = 0;
    int lfd = listen_local(&port);
    close(lfd); /* 立刻关闭：这个端口没人听 */

    upstream_profile_t up;
    memset(&up, 0, sizeof up);
    up.id = 2;
    up.type = UPSTREAM_HTTP;
    snprintf(up.host, sizeof up.host, "127.0.0.1");
    up.port = port;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int fd = -1;
    assert_int_equal(upstream_connect_http(&up, "example.test", 443, &fd), -1);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    assert_true(elapsed_ms(&t0, &t1) < 2000);
}

/* 上游类型分发：direct 连本地监听应当成功；NULL 一律失败 */
static void test_connect_profile_dispatch(void **s) {
    (void)s;
    uint16_t port = 0;
    int lfd = listen_local(&port);

    upstream_profile_t up;
    memset(&up, 0, sizeof up);
    up.id = 3;
    up.type = UPSTREAM_DIRECT;
    snprintf(up.name, sizeof up.name, "direct");

    int fd = -1;
    assert_int_equal(upstream_connect_profile(&up, "127.0.0.1", port, &fd), 0);
    assert_true(fd >= 0);
    close(fd);

    assert_int_equal(upstream_connect_profile(NULL, "127.0.0.1", port, &fd), -1);
    assert_int_equal(upstream_connect_profile(&up, "", port, &fd), -1);
    close(lfd);
}

/* 握手成功时，返回的 fd 上不能留着 SO_RCVTIMEO（否则 relay 阶段行为诡异） */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_http_handshake_times_out),
        cmocka_unit_test(test_http_refused_fails_fast),
        cmocka_unit_test(test_connect_profile_dispatch),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
