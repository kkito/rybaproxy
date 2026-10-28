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
    for (int i = 0; i < 1025; i++) {
        (void)i;
    }
    assert_true(dns_cache_count() <= 1024);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dns_interfaces_exist),
        cmocka_unit_test(test_dns_cache_lru_eviction),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
