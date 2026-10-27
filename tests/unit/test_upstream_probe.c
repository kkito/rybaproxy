#include <cmocka.h>
#include <string.h>
#include "rybaproxy/upstream.h"

static void test_probe_refused(void **state) {
    (void)state;
    upstream_profile_t u; memset(&u, 0, sizeof u);
    u.type = UPSTREAM_SOCKS5; snprintf(u.host, sizeof u.host, "127.0.0.1"); u.port = 1;
    long lat = -1;
    assert_int_not_equal(upstream_test_reachable(&u, 500, &lat), 0);
}

static void test_probe_direct_ok(void **state) {
    (void)state;
    upstream_profile_t u; memset(&u, 0, sizeof u);
    u.type = UPSTREAM_DIRECT;
    long lat = -1;
    assert_int_equal(upstream_test_reachable(&u, 500, &lat), 0);
    assert_int_equal((int)lat, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_probe_refused),
        cmocka_unit_test(test_probe_direct_ok),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
