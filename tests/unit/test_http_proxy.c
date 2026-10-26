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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_connect),
        cmocka_unit_test(test_get_absolute),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
