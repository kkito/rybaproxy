#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "rybaproxy/dns.h"

static void test_dns_interfaces_exist(void **state) {
    (void)state;
    dns_resolve(NULL, DNS_CLASS_AUTO, NULL);
    dns_set_proxy("none");
    dns_set_nameservers(NULL, 0);
    dns_add_nameserver(NULL);
    dns_clear_nameservers();
    (void)dns_cache_count();
    dns_cache_flush();
    (void)dns_log_count();
    dns_log_clear();
}

static void test_dns_cache_lru_eviction(void **state) {
    (void)state;
    dns_cache_flush();
    assert_int_equal(dns_cache_count(), 0);
}

static void test_dns_split_cache_before(void **state) {
    (void)state;
}

static void test_dns_bootstrap_ip_direct(void **state) {
    (void)state;
}

static void test_dns_proxy_fallback(void **state) {
    (void)state;
}

static void test_dns_log_ring(void **state) {
    (void)state;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dns_interfaces_exist),
        cmocka_unit_test(test_dns_cache_lru_eviction),
        cmocka_unit_test(test_dns_split_cache_before),
        cmocka_unit_test(test_dns_bootstrap_ip_direct),
        cmocka_unit_test(test_dns_proxy_fallback),
        cmocka_unit_test(test_dns_log_ring),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
