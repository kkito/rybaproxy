#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rybaproxy/config.h"
#include "rybaproxy/log.h"

static void test_config_defaults(void **state) {
    (void)state;
    config_t c;
    config_init_defaults(&c);
    assert_int_equal(c.http_port, 8080);
    assert_int_equal(c.socks5_port, 1080);
    assert_true(c.fallback_to_direct);
    assert_string_equal(c.default_upstream, "direct");
}

static void test_config_defaults_data_dir(void **state) {
    (void)state;
    /* 默认数据目录必须是用户家目录下，不能是 /var/lib（无权限） */
    config_t c;
    config_init_defaults(&c);
    assert_true(strstr(c.db_path, "/var/lib") == NULL);
    const char *home = getenv("HOME");
    if (home && *home) {
        char expect[300];
        snprintf(expect, sizeof expect, "%s/.local/rybaproxy/rybaproxy.db", home);
        assert_string_equal(c.db_path, expect);
    }
    assert_string_equal(c.geo_dir, "");
    assert_string_equal(c.log_level, "info");
    assert_int_equal(c.geo_cache_size, 512);
}

static void test_config_load_geo_dir(void **state) {
    (void)state;
    const char *path = "/tmp/ryba_cfg_geo_test.json";
    FILE *f = fopen(path, "w");
    assert_non_null(f);
    fputs("{\"geo_dir\":\"/tmp/mygeo\"}", f);
    fclose(f);
    config_t c;
    assert_int_equal(config_load(path, &c), 0);
    assert_string_equal(c.geo_dir, "/tmp/mygeo");
    config_free(&c);
    remove(path);
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

static void test_config_defaults_db_log_cache(void **s) {
    (void)s;
    /* RED: 默认 db/log 路径 + geo_cache_size(512) */
    config_t c;
    config_init_defaults(&c);
    const char *home = getenv("HOME");
    if (home && *home) {
        char expect[600];
        snprintf(expect, sizeof expect, "%s/.local/rybaproxy/rybaproxy.db", home);
        assert_string_equal(c.db_path, expect);
        snprintf(expect, sizeof expect, "%s/.local/rybaproxy/rybaproxy.log", home);
        assert_string_equal(c.log_file, expect);
    }
    assert_string_equal(c.log_level, "info");
    assert_int_equal(c.geo_cache_size, 512);
}

static void test_log_level_parse(void **s) {
    (void)s;
    /* RED(Task5): 级别名纯函数 */
    assert_int_equal(log_level_parse("debug"), LOG_DEBUG);
    assert_int_equal(log_level_parse("WARN"), LOG_WARN);
    assert_int_equal(log_level_parse("nonsense"), LOG_INFO);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_config_defaults),
        cmocka_unit_test(test_config_defaults_data_dir),
        cmocka_unit_test(test_config_load_geo_dir),
        cmocka_unit_test(test_config_load),
        cmocka_unit_test(test_config_defaults_db_log_cache),
        cmocka_unit_test(test_log_level_parse),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
