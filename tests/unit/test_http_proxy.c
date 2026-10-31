#include <cmocka.h>
#include "rybaproxy/http_proxy.h"
#include <string.h>

static void test_connect(void **state) {
    (void)state;
    const char *req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    http_request_info_t info;
    assert_int_equal(http_proxy_parse_request(req, strlen(req), &info), 0);
    assert_string_equal(info.method, "CONNECT");
    assert_true(info.is_connect);
    assert_string_equal(info.host, "example.com");
    assert_int_equal(info.port, 443);
}

static void test_get_absolute(void **state) {
    (void)state;
    const char *req = "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    http_request_info_t info;
    assert_int_equal(http_proxy_parse_request(req, strlen(req), &info), 0);
    assert_string_equal(info.method, "GET");
    assert_false(info.is_connect);
    assert_string_equal(info.host, "example.com");
    assert_int_equal(info.port, 80);
}

/* 回归：CONNECT 的 IPv6 目标必须完整解析。[2401:...]:443 曾被 strchr(':')
 * 砍在第一个冒号上，记成 host="[2401" port=67 → 连到错误目标且统计全错。 */
static void test_connect_ipv6(void **state) {
    (void)state;
    const char *req = "CONNECT [2401:67c:2b0::1]:8443 HTTP/1.1\r\nHost: [2401:67c:2b0::1]:8443\r\n\r\n";
    http_request_info_t info;
    assert_int_equal(http_proxy_parse_request(req, strlen(req), &info), 0);
    assert_string_equal(info.host, "2401:67c:2b0::1");
    assert_int_equal(info.port, 8443);
}

/* CONNECT 不带端口 → 默认 443 */
static void test_connect_default_port(void **state) {
    (void)state;
    const char *req = "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
    http_request_info_t info;
    assert_int_equal(http_proxy_parse_request(req, strlen(req), &info), 0);
    assert_string_equal(info.host, "example.com");
    assert_int_equal(info.port, 443);
}

/* 回归：绝对 URI 里的 IPv6 目标同样不能截断 */
static void test_get_absolute_ipv6(void **state) {
    (void)state;
    const char *req = "GET http://[2001:db8::1]:8080/x HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n";
    http_request_info_t info;
    assert_int_equal(http_proxy_parse_request(req, strlen(req), &info), 0);
    assert_string_equal(info.host, "2001:db8::1");
    assert_int_equal(info.port, 8080);
}

/* 绝对 URI 里的端口也要生效（不能被后面的 host 头覆盖回默认端口） */
static void test_get_absolute_with_port(void **state) {
    (void)state;
    const char *req = "GET http://example.com:8080/p HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    http_request_info_t info;
    assert_int_equal(http_proxy_parse_request(req, strlen(req), &info), 0);
    assert_string_equal(info.host, "example.com");
    assert_int_equal(info.port, 8080);
}

/* origin-form（只有 path）+ Host 头带端口 */
static void test_get_host_header_port(void **state) {
    (void)state;
    const char *req = "GET /x HTTP/1.1\r\nHost: a.example:8080\r\n\r\n";
    http_request_info_t info;
    assert_int_equal(http_proxy_parse_request(req, strlen(req), &info), 0);
    assert_string_equal(info.host, "a.example");
    assert_int_equal(info.port, 8080);
}

/* 拼回去时 IPv6 必须带方括号，否则 CONNECT 2401:67c::1:443 是坏请求 */
static void test_format_hostport(void **state) {
    (void)state;
    char out[64];
    format_hostport("2401:67c::1", 443, out, sizeof out);
    assert_string_equal(out, "[2401:67c::1]:443");
    format_hostport("example.com", 8080, out, sizeof out);
    assert_string_equal(out, "example.com:8080");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_connect),
        cmocka_unit_test(test_get_absolute),
        cmocka_unit_test(test_connect_ipv6),
        cmocka_unit_test(test_connect_default_port),
        cmocka_unit_test(test_get_absolute_ipv6),
        cmocka_unit_test(test_get_absolute_with_port),
        cmocka_unit_test(test_get_host_header_port),
        cmocka_unit_test(test_format_hostport),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
