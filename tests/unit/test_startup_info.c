/* 启动信息格式化单测：纯函数，锁输出格式，不碰任何 IO。 */
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "rybaproxy/common.h"
#include "rybaproxy/startup_info.h"

static startup_info_t mk(void) {
    startup_info_t i;
    memset(&i, 0, sizeof i);
    snprintf(i.version, sizeof i.version, "0.1.0");
    snprintf(i.commit, sizeof i.commit, "abc1234");
    snprintf(i.build_time, sizeof i.build_time, "2026-10-27T06:00:00");
    snprintf(i.config_path, sizeof i.config_path, "/home/u/.local/rybaproxy/config.json");
    snprintf(i.data_dir, sizeof i.data_dir, "/home/u/.local/rybaproxy");
    snprintf(i.db_path, sizeof i.db_path, "/home/u/.local/rybaproxy/rybaproxy.db");
    snprintf(i.log_file, sizeof i.log_file, "/home/u/.local/rybaproxy/rybaproxy.log");
    snprintf(i.log_level, sizeof i.log_level, "info");
    snprintf(i.pid_file, sizeof i.pid_file, "/home/u/.local/rybaproxy/rybaproxy.pid");
    i.pid = 4242;
    i.http_port = 8080;
    i.socks5_port = 1080;
    i.web_port = 9090;
    snprintf(i.web_url, sizeof i.web_url, "http://127.0.0.1:9090");
    i.upstream_count = 2;
    i.rule_count = 3;
    i.geo_ip_count = 10011;
    i.geo_site_count = 110276;
    i.geo_cache_size = 512;
    return i;
}

/* 基本信息必须一次说清：版本/路径/端口/上游/规则/geo，运维排查就靠这一屏 */
static void test_banner_has_all_facts(void **s) {
    (void)s;
    startup_info_t i = mk();
    char out[2048];
    size_t n = startup_info_text(&i, out, sizeof out);
    assert_true(n > 0);
    assert_non_null(strstr(out, "rybaproxy 0.1.0 (abc1234"));
    assert_non_null(strstr(out, "config    /home/u/.local/rybaproxy/config.json"));
    assert_non_null(strstr(out, "database  /home/u/.local/rybaproxy/rybaproxy.db"));
    assert_non_null(strstr(out, "log       /home/u/.local/rybaproxy/rybaproxy.log (info)"));
    assert_non_null(strstr(out, "pidfile   /home/u/.local/rybaproxy/rybaproxy.pid"));
    assert_non_null(strstr(out, "pid       4242"));
    assert_non_null(strstr(out, "listen    http 8080 | socks5 1080"));
    /* 管理页地址必须单独一行给出完整 URL，运维直接拷 */
    assert_non_null(strstr(out, "web       http://127.0.0.1:9090"));
    assert_non_null(strstr(out, "rules     3"));
    assert_non_null(strstr(out, "geo       ip=10011 site=110276 (cache 512)"));
}

/* 守护模式要在版本行标注，否则分不清前台/后台 */
static void test_banner_marks_detached(void **s) {
    (void)s;
    startup_info_t i = mk();
    char out[2048];
    i.detached = 1;
    startup_info_text(&i, out, sizeof out);
    assert_non_null(strstr(out, "[detached]"));
    i.detached = 0;
    startup_info_text(&i, out, sizeof out);
    assert_null(strstr(out, "[detached]"));
}

/* geo 库没加载时必须明确说出来，不能显示成 0 条误导人 */
static void test_banner_geo_not_loaded(void **s) {
    (void)s;
    startup_info_t i = mk();
    char out[2048];
    i.geo_ip_count = -1;
    i.geo_site_count = -1;
    startup_info_text(&i, out, sizeof out);
    assert_non_null(strstr(out, "geo       not loaded"));
    assert_null(strstr(out, "ip=-1"));
}

/* 输出必须截断而不是溢出：小 buffer 下返回长度受控 */
static void test_banner_truncates_safely(void **s) {
    (void)s;
    startup_info_t i = mk();
    char tiny[32];
    size_t n = startup_info_text(&i, tiny, sizeof tiny);
    assert_true(n < sizeof tiny);
    assert_int_equal(tiny[sizeof tiny - 1], '\0');
}

static void test_upstream_summary_empty(void **s) {
    (void)s;
    char out[256];
    assert_int_equal(upstream_summary(NULL, 0, out, sizeof out), 6);
    assert_string_equal(out, "(none)");
}

static void test_upstream_summary_lists(void **s) {
    (void)s;
    upstream_profile_t ups[2];
    memset(ups, 0, sizeof ups);
    ups[0].id = 0;
    snprintf(ups[0].name, sizeof ups[0].name, "proxy");
    ups[0].type = UPSTREAM_HTTP;
    snprintf(ups[0].host, sizeof ups[0].host, "172.27.128.253");
    ups[0].port = 7890;
    ups[0].enabled = 1;
    ups[1].id = 1;
    snprintf(ups[1].name, sizeof ups[1].name, "direct");
    ups[1].type = UPSTREAM_DIRECT;
    ups[1].enabled = 1;
    char out[512];
    upstream_summary(ups, 2, out, sizeof out);
    assert_string_equal(out, "proxy http://172.27.128.253:7890, direct");
}

/* 禁用项要标出来，否则排查时以为它在干活 */
static void test_upstream_summary_marks_disabled(void **s) {
    (void)s;
    upstream_profile_t ups[1];
    memset(ups, 0, sizeof ups);
    snprintf(ups[0].name, sizeof ups[0].name, "proxy");
    ups[0].type = UPSTREAM_HTTP;
    snprintf(ups[0].host, sizeof ups[0].host, "1.2.3.4");
    ups[0].port = 7890;
    ups[0].enabled = 0;
    char out[512];
    upstream_summary(ups, 1, out, sizeof out);
    assert_string_equal(out, "proxy http://1.2.3.4:7890 (off)");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_banner_has_all_facts),
        cmocka_unit_test(test_banner_marks_detached),
        cmocka_unit_test(test_banner_geo_not_loaded),
        cmocka_unit_test(test_banner_truncates_safely),
        cmocka_unit_test(test_upstream_summary_empty),
        cmocka_unit_test(test_upstream_summary_lists),
        cmocka_unit_test(test_upstream_summary_marks_disabled),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
