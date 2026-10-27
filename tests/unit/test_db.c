#include <cmocka.h>
#include <event2/event.h>
#include "rybaproxy/db.h"
#include "rybaproxy/router.h"
#include "rybaproxy/session.h"
#include "rybaproxy/web_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_db_roundtrip(void **state) {
    (void)state;
    char path[128];
    snprintf(path, sizeof path, "/tmp/ryba_db_test_%d.db", (int)getpid());
    /* cleanup */
    remove(path);
    char wal[160]; snprintf(wal,sizeof wal,"%s-wal",path); remove(wal);
    char shm[160]; snprintf(shm,sizeof shm,"%s-shm",path); remove(shm);

    assert_int_equal(db_init(path), 0);
    db_set_retention(90);
    db_start();

    struct event_base *base = event_base_new();
    session_t *s = session_create(base, PROTO_HTTP, "127.0.0.1");
    session_set_target(s, "example.com", 80);
    session_set_method(s, "GET");
    s->bytes_up = 12; s->bytes_down = 34;
    s->upstream_id = 0;
    session_finish(s, SESS_DONE, 0, NULL);
    db_enqueue_session(s, "direct");

    db_stop();
    session_destroy(s);
    event_base_free(base);

    /* reopen and count */
    /* db_stop closed handle; reopen via new init? Instead query file with sqlite not available in cmocka easily; use db_init again */
    assert_int_equal(db_init(path), 0);
    char buf[4096];
    assert_int_equal(db_get_recent_sessions(10, buf, sizeof buf), 0);
    /* should contain one session */
    assert_true(strstr(buf, "example.com") != NULL);
    db_stop();
    remove(path); remove(wal); remove(shm);
}

static void test_db_daily_agg(void **state) {
    (void)state;
    char path[128];
    snprintf(path, sizeof path, "/tmp/ryba_db_daily_%d.db", (int)getpid());
    remove(path);
    assert_int_equal(db_init(path), 0);
    db_start();
    struct event_base *base = event_base_new();
    session_t *s = session_create(base, PROTO_HTTP, "10.0.0.1");
    session_set_target(s, "example.com", 443);
    s->bytes_up = 100; s->bytes_down = 200;
    session_finish(s, SESS_DONE, 0, NULL);
    db_enqueue_session(s, "direct");
    db_stop();
    session_destroy(s); event_base_free(base);
    assert_int_equal(db_init(path), 0);
    char buf[8192];
    assert_int_equal(db_stats_daily(30, buf, sizeof buf), 0);
    assert_true(strstr(buf, "bytes_down") != NULL);
    db_stop();
    remove(path);
}

static void rm_db(const char *path) {
    char tmp[192];
    remove(path);
    snprintf(tmp, sizeof tmp, "%s-wal", path); remove(tmp);
    snprintf(tmp, sizeof tmp, "%s-shm", path); remove(tmp);
    snprintf(tmp, sizeof tmp, "%s-journal", path); remove(tmp);
}

static void test_db_filter_pagination(void **state) {
    (void)state;
    char path[128];
    snprintf(path, sizeof path, "/tmp/ryba_db_filt_%d.db", (int)getpid());
    rm_db(path);
    assert_int_equal(db_init(path), 0);
    db_start();
    struct event_base *base = event_base_new();
    const char *clients[3] = {"10.0.0.1", "10.0.0.2", "192.168.1.9"};
    for (int i = 0; i < 3; i++) {
        session_t *s = session_create(base, PROTO_HTTP, clients[i]);
        session_set_target(s, "example.com", 80);
        s->bytes_up = 10; s->bytes_down = 20;
        session_finish(s, SESS_DONE, 0, NULL);
        db_enqueue_session(s, "direct");
        session_destroy(s);
    }
    db_stop();
    event_base_free(base);
    assert_int_equal(db_init(path), 0);
    char buf[8192]; int total = 0;
    assert_int_equal(db_query_sessions("10.0.0", NULL, -1, 2, 0, buf, sizeof buf, &total), 0);
    assert_int_equal(total, 2);
    assert_true(strstr(buf, "\"limit\":2") != NULL);
    assert_int_equal(db_query_sessions(NULL, NULL, -1, 2, 1, buf, sizeof buf, &total), 0);
    assert_int_equal(total, 3);
    assert_true(strstr(buf, "\"offset\":1") != NULL);
    assert_int_equal(db_query_sessions(NULL, "no-such-host", -1, 10, 0, buf, sizeof buf, &total), 0);
    assert_int_equal(total, 0);
    assert_true(strstr(buf, "\"data\":[]") != NULL);
    db_stop();
    rm_db(path);
}

static void test_db_summary_top(void **state) {
    (void)state;
    char path[128];
    snprintf(path, sizeof path, "/tmp/ryba_db_sum_%d.db", (int)getpid());
    rm_db(path);
    assert_int_equal(db_init(path), 0);
    db_start();
    struct event_base *base = event_base_new();
    session_t *s = session_create(base, PROTO_SOCKS5, "10.1.1.1");
    session_set_target(s, "big.example.com", 443);
    s->bytes_up = 1000; s->bytes_down = 2000;
    session_finish(s, SESS_ERROR, 5, NULL);
    db_enqueue_session(s, "office");
    session_destroy(s);
    db_stop();
    event_base_free(base);
    assert_int_equal(db_init(path), 0);
    char buf[8192];
    assert_int_equal(db_stats_summary(0, 0, buf, sizeof buf), 0);
    assert_true(strstr(buf, "\"sessions\":1") != NULL);
    assert_true(strstr(buf, "\"bytes_down\":2000") != NULL);
    assert_true(strstr(buf, "\"errors\":1") != NULL);
    assert_int_equal(db_stats_top("target", 10, 0, 0, buf, sizeof buf), 0);
    assert_true(strstr(buf, "big.example.com") != NULL);
    assert_int_equal(db_stats_top("client", 10, 0, 0, buf, sizeof buf), 0);
    assert_true(strstr(buf, "10.1.1.1") != NULL);
    assert_int_equal(db_stats_top("bogus", 10, 0, 0, buf, sizeof buf), -2);
    db_stop();
    rm_db(path);
}

static void test_db_settings(void **state) {
    (void)state;
    char path[128];
    snprintf(path, sizeof path, "/tmp/ryba_db_set_%d.db", (int)getpid());
    rm_db(path);
    assert_int_equal(db_init(path), 0);
    assert_int_equal(db_settings_set("retention_days", "90"), 0);
    char buf[1024];
    assert_int_equal(db_settings_get(buf, sizeof buf), 0);
    assert_true(strstr(buf, "retention_days") != NULL);
    assert_int_not_equal(db_settings_set("", "x"), 0);
    db_stop();
    rm_db(path);
}

static void test_db_empty_daily(void **state) {
    (void)state;
    char path[128];
    snprintf(path, sizeof path, "/tmp/ryba_db_empty_%d.db", (int)getpid());
    rm_db(path);
    assert_int_equal(db_init(path), 0);
    char buf[256];
    assert_int_equal(db_stats_daily(30, buf, sizeof buf), 0);
    assert_string_equal(buf, "[]");
    int total = -1;
    assert_int_equal(db_query_sessions(NULL, NULL, -1, 10, 0, buf, sizeof buf, &total), 0);
    assert_int_equal(total, 0);
    db_stop();
    rm_db(path);
}

static void test_db_rules_geo_roundtrip(void **state) {
    (void)state;
    char path[128];
    snprintf(path, sizeof path, "/tmp/ryba_db_rules_%d.db", (int)getpid());
    rm_db(path);
    assert_int_equal(db_init(path), 0);
    rule_t r; memset(&r, 0, sizeof r);
    r.id = 7; r.priority = 100; r.enabled = 1;
    snprintf(r.name, sizeof r.name, "cn-ip");
    snprintf(r.geo_ip, sizeof r.geo_ip, "cn");
    snprintf(r.geo_site, sizeof r.geo_site, "!cn");
    r.upstream_id = 3;
    assert_int_equal(web_rules_db_save(&r), 0);
    router_t rt; router_init(&rt, "direct", 1);
    assert_int_equal(web_rules_db_load_all(&rt), 0);
    assert_int_equal(rt.count, 1);
    assert_int_equal(rt.rules[0].id, 7);
    assert_string_equal(rt.rules[0].geo_ip, "cn");
    assert_string_equal(rt.rules[0].geo_site, "!cn");
    assert_int_equal(rt.rules[0].upstream_id, 3);
    assert_int_equal(rt.next_rule_id, 8);
    router_free(&rt);
    db_stop();
    rm_db(path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_db_roundtrip),
        cmocka_unit_test(test_db_daily_agg),
        cmocka_unit_test(test_db_filter_pagination),
        cmocka_unit_test(test_db_summary_top),
        cmocka_unit_test(test_db_settings),
        cmocka_unit_test(test_db_empty_daily),
        cmocka_unit_test(test_db_rules_geo_roundtrip),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
