#include <cmocka.h>
#include <event2/event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rybaproxy/db.h"
#include "rybaproxy/geo.h"
#include "rybaproxy/session.h"
#include "rybaproxy/web_api.h"
#include "rybaproxy/router.h"

static char g_tmpdb[128];

static int setup(void **state) {
    (void)state;
    snprintf(g_tmpdb, sizeof g_tmpdb, "/tmp/ryba_webapi_%d.db", (int)getpid());
    char tmp[192];
    remove(g_tmpdb);
    snprintf(tmp, sizeof tmp, "%s-wal", g_tmpdb); remove(tmp);
    snprintf(tmp, sizeof tmp, "%s-shm", g_tmpdb); remove(tmp);
    snprintf(tmp, sizeof tmp, "%s-journal", g_tmpdb); remove(tmp);
    assert_int_equal(db_init(g_tmpdb), 0);
    return 0;
}

static int teardown(void **state) {
    (void)state;
    db_stop();
    char tmp[192];
    remove(g_tmpdb);
    snprintf(tmp, sizeof tmp, "%s-wal", g_tmpdb); remove(tmp);
    snprintf(tmp, sizeof tmp, "%s-shm", g_tmpdb); remove(tmp);
    snprintf(tmp, sizeof tmp, "%s-journal", g_tmpdb); remove(tmp);
    return 0;
}

static void test_envelope_ok_shape(void **state) {
    (void)state;
    char *s = web_envelope_json("{\"a\":1}", NULL, NULL);
    assert_non_null(s);
    assert_true(strstr(s, "\"ok\":true") != NULL);
    assert_true(strstr(s, "\"data\":{\"a\":1}") != NULL);
    free(s);
}

static void test_envelope_err_shape(void **state) {
    (void)state;
    char *s = web_envelope_json(NULL, "NOT_FOUND", "nope");
    assert_non_null(s);
    assert_true(strstr(s, "\"ok\":false") != NULL);
    assert_true(strstr(s, "NOT_FOUND") != NULL);
    free(s);
}

static void test_envelope_paged_shape(void **state) {
    (void)state;
    char *s = web_envelope_paged("{\"data\":[],\"total\":0,\"limit\":10,\"offset\":5}");
    assert_non_null(s);
    assert_true(strstr(s, "\"ok\":true") != NULL);
    assert_true(strstr(s, "\"total\":0") != NULL);
    free(s);
}

static void test_stats_daily_empty_db(void **state) {
    (void)state;
    char buf[256];
    assert_int_equal(db_stats_daily(30, buf, sizeof buf), 0);
    assert_string_equal(buf, "[]");
    char *s = web_envelope_json(buf, NULL, NULL);
    assert_true(strstr(s, "\"data\":[]") != NULL);
    free(s);
}

static void test_sessions_pagination_shape(void **state) {
    (void)state;
    char buf[4096]; int total = -1;
    assert_int_equal(db_query_sessions(NULL, NULL, -1, 10, 5, buf, sizeof buf, &total), 0);
    assert_int_equal(total, 0);
    char *s = web_envelope_paged(buf);
    assert_true(strstr(s, "\"limit\":10") != NULL);
    assert_true(strstr(s, "\"offset\":5") != NULL);
    free(s);
}

static void test_top_invalid(void **state) {
    (void)state;
    char buf[256];
    assert_int_equal(db_stats_top("bogus", 10, 0, 0, buf, sizeof buf), -2);
}

static void test_rule_reload_sorts(void **state) {
    (void)state;
    router_t r; router_init(&r, "direct", 1);
    rule_t a; memset(&a, 0, sizeof a); a.id = 1; a.priority = 100; a.enabled = 1;
    rule_t b; memset(&b, 0, sizeof b); b.id = 2; b.priority = 10; b.enabled = 1;
    router_add_rule(&r, &a);
    router_add_rule(&r, &b);
    assert_int_equal(web_rules_reload(&r), 0);
    assert_int_equal(r.rules[0].priority, 10);
    assert_int_equal(r.rules[1].priority, 100);
    router_free(&r);
}

static void test_upstream_update_not_found(void **state) {
    (void)state;
    server_ctx_t srv; memset(&srv, 0, sizeof srv);
    pthread_mutex_init(&srv.lock, NULL);
    char *out = NULL; int status = 0;
    assert_int_equal(web_upstreams_update(&srv, 9999, "{\"name\":\"x\"}", &out, &status), 0);
    assert_int_equal(status, 404);
    assert_true(strstr(out, "NOT_FOUND") != NULL);
    free(out);
    pthread_mutex_destroy(&srv.lock);
}

static void test_upstream_update_auth_persist(void **state) {
    (void)state;
    server_ctx_t srv; memset(&srv, 0, sizeof srv);
    pthread_mutex_init(&srv.lock, NULL);
    srv.upstreams = calloc(1, sizeof(upstream_profile_t));
    srv.upstream_count = 1;
    srv.upstreams[0].id = 7;
    char *out = NULL; int status = 0;
    assert_int_equal(web_upstreams_update(&srv, 7, "{\"username\":\"admin\",\"password\":\"s3cret\"}", &out, &status), 0);
    assert_int_equal(status, 200);
    assert_string_equal(srv.upstreams[0].username, "admin");
    assert_string_equal(srv.upstreams[0].password, "s3cret");
    free(out);
    /* password omitted in PUT => must keep old secret (no wipe) */
    assert_int_equal(web_upstreams_update(&srv, 7, "{\"name\":\"hk\"}", &out, &status), 0);
    assert_string_equal(srv.upstreams[0].username, "admin");
    assert_string_equal(srv.upstreams[0].password, "s3cret");
    free(out);
    free(srv.upstreams);
    pthread_mutex_destroy(&srv.lock);
}

static void test_upstream_update_ok(void **state) {
    (void)state;
    server_ctx_t srv; memset(&srv, 0, sizeof srv);
    pthread_mutex_init(&srv.lock, NULL);
    srv.upstreams = calloc(1, sizeof(upstream_profile_t));
    srv.upstream_count = 1;
    srv.upstreams[0].id = 7;
    snprintf(srv.upstreams[0].name, sizeof srv.upstreams[0].name, "old");
    char *out = NULL; int status = 0;
    assert_int_equal(web_upstreams_update(&srv, 7, "{\"name\":\"new\",\"enabled\":false}", &out, &status), 0);
    assert_int_equal(status, 200);
    assert_string_equal(srv.upstreams[0].name, "new");
    assert_int_equal(srv.upstreams[0].enabled, 0);
    free(out);
    free(srv.upstreams);
    pthread_mutex_destroy(&srv.lock);
}

static void test_session_get_by_id(void **state) {
    (void)state;
    db_start();
    struct event_base *base = event_base_new();
    session_t *s = session_create(base, PROTO_HTTP, "9.9.9.9");
    session_set_target(s, "one.example.com", 80);
    session_finish(s, SESS_DONE, 0, NULL);
    long long id = (long long)s->id;
    db_enqueue_session(s, "direct");
    db_stop();
    session_destroy(s); event_base_free(base);
    assert_int_equal(db_init(g_tmpdb), 0);
    char buf[2048];
    assert_int_equal(db_get_session_by_id(id, buf, sizeof buf), 0);
    assert_true(strstr(buf, "one.example.com") != NULL);
    assert_int_equal(db_get_session_by_id(999999999LL, buf, sizeof buf), 1);
}

static void test_geo_url_override(void **state) {
    (void)state;
    /* 默认源 + 环境变量覆盖：换源不用改代码 */
    assert_true(strstr(geo_ip_url(), "geoip.dat") != NULL);
    assert_true(strstr(geo_site_url(), "geosite.dat") != NULL);
    setenv("RYBA_GEOIP_URL", "https://example.com/x.dat", 1);
    assert_string_equal(geo_ip_url(), "https://example.com/x.dat");
    unsetenv("RYBA_GEOIP_URL");
}

static void test_geo_check_validation(void **state) {
    (void)state;
    /* check 入参：空 host 拒绝（400 语义）；geo 三值语义抽查 */
    assert_int_equal(geo_site_is_cn(""), -1);
    assert_int_equal(geo_ip_is_cn(""), -1);
}

static void test_rule_geo_validation(void **state) {
    (void)state;
    /* 白名单校验：非法值拒绝，合法值 + 空值通过 */
    assert_int_equal(valid_geo(""), 1);
    assert_int_equal(valid_geo("cn"), 1);
    assert_int_equal(valid_geo("!cn"), 1);
    assert_int_equal(valid_geo("lan"), 1);
    assert_int_equal(valid_geo("!lan"), 1);
    assert_int_equal(valid_geo("us"), 0);
    assert_int_equal(valid_geo("CN"), 0);
}

static void test_settings_roundtrip(void **state) {
    (void)state;
    assert_int_equal(db_settings_set("k1", "v1"), 0);
    char buf[512];
    assert_int_equal(db_settings_get(buf, sizeof buf), 0);
    char *s = web_envelope_json(buf, NULL, NULL);
    assert_true(strstr(s, "k1") != NULL);
    free(s);
}

static void test_geo_unknown_json_shape(void **state) {
    (void)state;
    /* 空库 /api/geo/check 语义：未知输出 null（不是 false），页面据此报“库未加载” */
    geo_test_reset();
    assert_int_equal(geo_ip_is_cn("110.242.69.21"), -1);
    assert_int_equal(geo_site_is_cn("www.baidu.com"), -1);
    assert_int_equal(geo_host_is_cn("1.2.3.9"), -1);
    geo_free();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_envelope_ok_shape),
        cmocka_unit_test(test_envelope_err_shape),
        cmocka_unit_test(test_envelope_paged_shape),
        cmocka_unit_test_setup_teardown(test_stats_daily_empty_db, setup, teardown),
        cmocka_unit_test_setup_teardown(test_sessions_pagination_shape, setup, teardown),
        cmocka_unit_test(test_top_invalid),
        cmocka_unit_test(test_rule_reload_sorts),
        cmocka_unit_test(test_upstream_update_not_found),
        cmocka_unit_test(test_upstream_update_ok),
        cmocka_unit_test(test_upstream_update_auth_persist),
        cmocka_unit_test(test_rule_geo_validation),
        cmocka_unit_test(test_geo_check_validation),
        cmocka_unit_test(test_geo_url_override),
        cmocka_unit_test(test_geo_unknown_json_shape),
        cmocka_unit_test_setup_teardown(test_session_get_by_id, setup, teardown),
        cmocka_unit_test_setup_teardown(test_settings_roundtrip, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
