#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "rybaproxy/dns.h"

static void test_dns_interfaces_exist(void **state) {
    (void)state;
    /* Just check symbols link */
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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dns_interfaces_exist),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
