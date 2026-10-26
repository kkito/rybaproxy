#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include "rybaproxy/config.h"

static void test_config_defaults(void **state) {
    (void)state;
    config_t c;
    config_init_defaults(&c);
    assert_int_equal(c.http_port, 8080);
    assert_int_equal(c.socks5_port, 1080);
    assert_true(c.fallback_to_direct);
    assert_string_equal(c.default_upstream, "direct");
}

static void test_config_load(void **state) {
    (void)state;
    const char *path = "/tmp/ryba_cfg_test.json";
    FILE *f = fopen(path, "w");
    assert_non_null(f);
    fputs("{\"http_port\":9090,\"limits\":{\"max_connections\":5},\"routing\":{\"default_upstream\":\"corp\"}}", f);
    fclose(f);
    config_t c;
    assert_int_equal(config_load(path, &c), 0);
    assert_int_equal(c.http_port, 9090);
    assert_int_equal(c.max_connections, 5);
    assert_string_equal(c.default_upstream, "corp");
    remove(path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_config_defaults),
        cmocka_unit_test(test_config_load),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
