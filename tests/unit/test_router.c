#include <cmocka.h>
#include "rybaproxy/router.h"
#include <string.h>

static void test_domain_wildcard(void **state) {
    (void)state;
    assert_int_equal(match_domain("*.example.com", "a.example.com"), 1);
    assert_int_equal(match_domain("*.example.com", "example.com"), 0);
    assert_int_equal(match_domain(".example.com", "example.com"), 1);
    assert_int_equal(match_domain(".example.com", "x.example.com"), 1);
}

static void test_cidr(void **state) {
    (void)state;
    assert_int_equal(match_cidr("10.0.0.0/8", "10.5.6.7"), 1);
    assert_int_equal(match_cidr("10.0.0.0/8", "192.168.1.1"), 0);
}

static void test_select(void **state) {
    (void)state;
    router_t r;
    router_init(&r, "direct", true);
    rule_t rule = {0};
    rule.id = 1; rule.priority = 100; rule.enabled = 1;
    strcpy(rule.domain_pattern, "*.example.com");
    rule.upstream_id = 42;
    router_add_rule(&r, &rule);
    assert_int_equal(router_select(&r, "a.example.com", 443, PROTO_HTTP, "1.2.3.4"), 42);
    assert_int_equal(router_select(&r, "other.com", 443, PROTO_HTTP, "1.2.3.4"), -1);
    router_free(&r);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_domain_wildcard),
        cmocka_unit_test(test_cidr),
        cmocka_unit_test(test_select),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
