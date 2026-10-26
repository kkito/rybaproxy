#include <cmocka.h>
#include "rybaproxy/socks5.h"

static void test_parse_ipv4(void **state) {
    (void)state;
    unsigned char buf[] = {0x05,0x01,0x00,0x01, 1,2,3,4, 0x00,0x50};
    char host[64]; uint16_t port=0;
    int n = socks5_parse_request(buf, sizeof buf, host, sizeof host, &port);
    assert_int_equal(n, 10);
    assert_string_equal(host, "1.2.3.4");
    assert_int_equal(port, 80);
}

static void test_parse_domain(void **state) {
    (void)state;
    unsigned char buf[] = {0x05,0x01,0x00,0x03, 0x0b, 'e','x','a','m','p','l','e','.','c','o','m', 0x01,0xbb};
    char host[64]; uint16_t port=0;
    int n = socks5_parse_request(buf, sizeof buf, host, sizeof host, &port);
    assert_int_equal(n, 18);
    assert_string_equal(host, "example.com");
    assert_int_equal(port, 443);
}

static void test_reply(void **state) {
    (void)state;
    unsigned char out[10];
    int n = socks5_build_reply(out, 0);
    assert_int_equal(n, 10);
    assert_int_equal(out[1], 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_ipv4),
        cmocka_unit_test(test_parse_domain),
        cmocka_unit_test(test_reply),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
