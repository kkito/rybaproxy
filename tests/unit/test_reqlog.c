#include <cmocka.h>
#include <string.h>

#include "rybaproxy/reqlog.h"

/* 请求日志格式化：纯函数，输入 → 一行文本。 */

static void test_route_line_all_fields(void **s) {
    (void)s;
    reqlog_route_t r;
    memset(&r, 0, sizeof r);
    r.id = 42;
    r.client = "192.168.1.5";
    r.host = "www.bing.com";
    r.port = 443;
    r.proto = "HTTP";
    r.method = "CONNECT";
    r.rule_id = 3;
    r.rule_name = "cn-ip-direct";
    r.upstream = "direct";
    r.geo_site = 0;
    r.geo_host = 1;
    r.geo_lan = 0;
    char buf[512];
    size_t n = reqlog_format_route(buf, sizeof buf, &r);
    assert_true(n > 0);
    assert_string_equal(buf,
        "[42] 路由 host=www.bing.com:443 proto=HTTP method=CONNECT client=192.168.1.5 "
        "rule=3/cn-ip-direct upstream=direct geo=site:0,ip:1,lan:0");
    assert_int_equal((int)n, (int)strlen(buf));
}

/* 没命中规则 / 没查过的 geo 用 - 和 default 表示，不能写成 0 误导人 */
static void test_route_line_unknowns(void **s) {
    (void)s;
    reqlog_route_t r;
    memset(&r, 0, sizeof r);
    r.id = 7;
    r.client = "10.0.0.2";
    r.host = "example.org";
    r.port = 80;
    r.proto = "SOCKS5";
    r.method = NULL;
    r.rule_id = -1;
    r.rule_name = NULL;
    r.upstream = "foreign-7891";
    r.geo_site = -1;
    r.geo_host = -1;
    r.geo_lan = -1;
    char buf[512];
    reqlog_format_route(buf, sizeof buf, &r);
    assert_string_equal(buf,
        "[7] 路由 host=example.org:80 proto=SOCKS5 method=- client=10.0.0.2 "
        "rule=-/default upstream=foreign-7891 geo=site:-,ip:-,lan:-");
}

static void test_connect_line(void **s) {
    (void)s;
    char buf[256];
    reqlog_format_connect(buf, sizeof buf, 42, "direct", 1, 12, NULL);
    assert_string_equal(buf, "[42] 连接 upstream=direct ok ms=12");
    reqlog_format_connect(buf, sizeof buf, 43, "foreign-7891", 0, 10003, "timeout");
    assert_string_equal(buf, "[43] 连接 upstream=foreign-7891 fail ms=10003 err=timeout");
}

static void test_finish_line(void **s) {
    (void)s;
    char buf[256];
    reqlog_format_finish(buf, sizeof buf, 42, "www.bing.com", 443, 0, 1345, 1234, 98765, NULL);
    assert_string_equal(buf,
        "[42] 结束 host=www.bing.com:443 status=ok dur=1345ms up=1234 down=98765");
    reqlog_format_finish(buf, sizeof buf, 44, "x.test", 80, 502, 3001, 0, 0, "connect_failed");
    assert_string_equal(buf,
        "[44] 结束 host=x.test:80 status=502 dur=3001ms up=0 down=0 err=connect_failed");
}

/* 缓冲区太小必须安全截断，不能越界 */
static void test_truncation_is_safe(void **s) {
    (void)s;
    reqlog_route_t r;
    memset(&r, 0, sizeof r);
    r.id = 1;
    r.client = "1.1.1.1";
    r.host = "averylonghostname.example.com";
    r.port = 443;
    r.proto = "HTTP";
    r.rule_id = -1;
    r.upstream = "direct";
    r.geo_site = r.geo_host = r.geo_lan = -1;
    char small[24];
    memset(small, 'X', sizeof small);
    size_t n = reqlog_format_route(small, sizeof small, &r);
    assert_int_equal((int)strlen(small), (int)sizeof small - 1);
    assert_true(n >= strlen(small));
    /* 'X' 必须被覆盖掉，说明确实写了内容而不是原样不动 */
    assert_null((void *)strchr(small, 'X'));
}

static void test_null_args(void **s) {
    (void)s;
    char buf[64];
    assert_int_equal((int)reqlog_format_route(buf, sizeof buf, NULL), 0);
    assert_int_equal((int)reqlog_format_route(NULL, 0, NULL), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_route_line_all_fields),
        cmocka_unit_test(test_route_line_unknowns),
        cmocka_unit_test(test_connect_line),
        cmocka_unit_test(test_finish_line),
        cmocka_unit_test(test_truncation_is_safe),
        cmocka_unit_test(test_null_args),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
