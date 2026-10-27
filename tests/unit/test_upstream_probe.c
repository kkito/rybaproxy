#include <cmocka.h>
#include <string.h>
#include "rybaproxy/upstream.h"
#include "rybaproxy/common.h"

static void test_probe_refused(void **state) {
    (void)state;
    upstream_profile_t u; memset(&u, 0, sizeof u);
    u.type = UPSTREAM_SOCKS5; snprintf(u.host, sizeof u.host, "127.0.0.1"); u.port = 1;
    long lat = -1;
    assert_int_not_equal(upstream_test_reachable(&u, 500, &lat), 0);
}

static void test_probe_direct_ok(void **state) {
    (void)state;
    upstream_profile_t u; memset(&u, 0, sizeof u);
    u.type = UPSTREAM_DIRECT;
    long lat = -1;
    assert_int_equal(upstream_test_reachable(&u, 500, &lat), 0);
    assert_int_equal((int)lat, 0);
}

/* ---- 路由结果 → 上游下标 的纯函数 ---- */
static void fill_ups(upstream_profile_t *u) {
    memset(u, 0, sizeof(upstream_profile_t) * 3);
    u[0].id = 0; snprintf(u[0].name, sizeof u[0].name, "proxy");  u[0].type = UPSTREAM_HTTP;   u[0].enabled = 1;
    u[1].id = 1; snprintf(u[1].name, sizeof u[1].name, "direct"); u[1].type = UPSTREAM_DIRECT; u[1].enabled = 1;
    u[2].id = 2; snprintf(u[2].name, sizeof u[2].name, "backup"); u[2].type = UPSTREAM_SOCKS5; u[2].enabled = 1;
}

static void test_pick_route_id_wins(void **state) {
    (void)state;
    upstream_profile_t u[3]; fill_ups(u);
    assert_int_equal(upstream_pick(u, 3, "direct", 2), 2);
}

static void test_pick_default_when_no_route(void **state) {
    (void)state;
    upstream_profile_t u[3]; fill_ups(u);
    assert_int_equal(upstream_pick(u, 3, "backup", -1), 2);
}

static void test_pick_fallback_direct_when_id_unknown(void **state) {
    (void)state;
    upstream_profile_t u[3]; fill_ups(u);
    /* 规则指向不存在的 id：回落 direct，而不是回落 id=0 */
    assert_int_equal(upstream_pick(u, 3, "backup", 99), 1);
}

static void test_pick_bad_id_falls_back_to_direct(void **state) {
    (void)state;
    upstream_profile_t u[3]; fill_ups(u);
    /* 规则指向不存在的 id：回落 direct，绝不能回落成 id=0 的 proxy */
    assert_int_equal(upstream_pick(u, 3, "nope", 99), 1);
    assert_int_equal(upstream_pick(u, 3, "nope", -1), 1);
}

static void test_pick_minus_one_when_nothing_usable(void **state) {
    (void)state;
    upstream_profile_t u[3]; fill_ups(u);
    u[1].enabled = 0; /* direct 也禁用：无处可去，返回 -1 让调用方补建 direct */
    assert_int_equal(upstream_pick(u, 3, "nope", 99), -1);
    assert_int_equal(upstream_pick(u, 3, "nope", -1), -1);
    assert_int_equal(upstream_pick(u, 0, "direct", -1), -1);
}

static void test_pick_disabled_skipped(void **state) {
    (void)state;
    upstream_profile_t u[3]; fill_ups(u);
    u[1].enabled = 0; /* direct 被禁用 */
    assert_int_equal(upstream_pick(u, 3, "backup", 99), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_probe_refused),
        cmocka_unit_test(test_probe_direct_ok),
        cmocka_unit_test(test_pick_route_id_wins),
        cmocka_unit_test(test_pick_default_when_no_route),
        cmocka_unit_test(test_pick_fallback_direct_when_id_unknown),
        cmocka_unit_test(test_pick_bad_id_falls_back_to_direct),
        cmocka_unit_test(test_pick_minus_one_when_nothing_usable),
        cmocka_unit_test(test_pick_disabled_skipped),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
