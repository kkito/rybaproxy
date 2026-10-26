#include <cmocka.h>
#include "rybaproxy/router.h"
#include <string.h>

static void test_domain_wildcard(void **state) {
    (void)state;
    assert_int_equal(match_domain("*.example.com", "a.example.com"), 1);
    assert_int_equal(match_domain("*.example.com", "example.com"), 0);
    assert_int_equal(match_domain(".example.com", "example.com"), 1);
    assert_int_equal(match_domain(".example.com", "x.example.com"), 1);
    assert_int_equal(match_domain("example.com", "EXAMPLE.COM"), 1);
    assert_int_equal(match_domain("*", "anything.com"), 1);
}

static void test_cidr(void **state) {
    (void)state;
    assert_int_equal(match_cidr("10.0.0.0/8", "10.5.6.7"), 1);
    assert_int_equal(match_cidr("10.0.0.0/8", "192.168.1.1"), 0);
    assert_int_equal(match_cidr("192.168.1.5", "192.168.1.5"), 1);
}

static void test_select_priority(void **state) {
    (void)state;
    router_t r;
    router_init(&r, "direct", true);
    rule_t r1 = {0}; r1.id=1; r1.priority=10; r1.enabled=1; strcpy(r1.domain_pattern,"*.example.com"); r1.upstream_id=10;
    rule_t r2 = {0}; r2.id=2; r2.priority=20; r2.enabled=1; strcpy(r2.domain_pattern,"*.example.com"); r2.upstream_id=20;
    router_add_rule(&r, &r1);
    router_add_rule(&r, &r2);
    assert_int_equal(router_select(&r, "a.example.com", 443, PROTO_HTTP, "1.2.3.4"), 20);
    router_free(&r);
}

static void test_select_default(void **state) {
    (void)state;
    router_t r;
    router_init(&r, "direct", true);
    /* no rules -> no match -> -1 (caller uses default) */
    assert_int_equal(router_select(&r, "other.com", 80, PROTO_HTTP, "1.2.3.4"), -1);
    router_free(&r);
}

static void test_remove_rule(void **state) {
    (void)state;
    router_t r;
    router_init(&r, "direct", true);
    rule_t rule = {0}; rule.id=5; rule.priority=1; rule.enabled=1; strcpy(rule.domain_pattern,"x.com"); rule.upstream_id=9;
    router_add_rule(&r, &rule);
    assert_int_equal(router_remove_rule(&r, 5), 0);
    assert_int_equal(r.count, 0);
    assert_int_equal(router_remove_rule(&r, 5), -1);
    router_free(&r);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_domain_wildcard),
        cmocka_unit_test(test_cidr),
        cmocka_unit_test(test_select_priority),
        cmocka_unit_test(test_select_default),
        cmocka_unit_test(test_remove_rule),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
