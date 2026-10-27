#include <cmocka.h>
#include "rybaproxy/router.h"
#include "rybaproxy/geo.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

/* geo 条件单测：构造迷你 wire dat 预置 1.2.3.0/24 + suffix example.cn */
static const unsigned char kIpEntry[] = {
    0x0A, 0x02, 'C', 'N',
    0x12, 0x08, 0x0A, 0x04, 1, 2, 3, 0, 0x10, 0x18,
};
static const unsigned char kSiteEntry[] = {
    0x0A, 0x02, 'C', 'N',
    0x12, 0x0E, 0x08, 0x02,
    0x12, 0x0A, 'e','x','a','m','p','l','e','.','c','n',
};
static char g_dir[128];
static int geo_setup(void **s) {
    (void)s;
    snprintf(g_dir, sizeof g_dir, "/tmp/ryba_rgeo_%d", (int)getpid());
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -rf %s && mkdir -p %s", g_dir, g_dir);
    if (system(cmd) != 0) return -1;
    char path[256];
    snprintf(path, sizeof path, "%s/geoip.dat", g_dir);
    FILE *f = fopen(path, "wb");
    unsigned char h[2] = { 0x0A, (unsigned char)sizeof kIpEntry };
    fwrite(h, 1, 2, f); fwrite(kIpEntry, 1, sizeof kIpEntry, f); fclose(f);
    snprintf(path, sizeof path, "%s/geosite.dat", g_dir);
    f = fopen(path, "wb");
    h[1] = (unsigned char)sizeof kSiteEntry;
    fwrite(h, 1, 2, f); fwrite(kSiteEntry, 1, sizeof kSiteEntry, f); fclose(f);
    geo_init();
    if (geo_load(g_dir) != 0) return -1;
    return 0;
}
static int geo_teardown(void **s) {
    (void)s;
    geo_free();
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -rf %s", g_dir);
    (void)system(cmd);
    return 0;
}
static void test_rule_geo_ip_cn(void **s) {
    (void)s;
    router_t r; router_init(&r, "direct", 1);
    rule_t rule = {0}; rule.id=1; rule.priority=100; rule.enabled=1;
    strcpy(rule.geo_ip, "cn"); rule.upstream_id=5;
    router_add_rule(&r, &rule);
    assert_int_equal(router_select(&r, "1.2.3.9", 80, PROTO_HTTP, NULL), 5);
    assert_int_equal(router_select(&r, "9.9.9.9", 80, PROTO_HTTP, NULL), -1);
    router_free(&r);
}
static void test_rule_geo_ip_neg(void **s) {
    (void)s;
    router_t r; router_init(&r, "direct", 1);
    rule_t rule = {0}; rule.id=1; rule.priority=100; rule.enabled=1;
    strcpy(rule.geo_ip, "!cn"); rule.upstream_id=6;
    router_add_rule(&r, &rule);
    assert_int_equal(router_select(&r, "9.9.9.9", 80, PROTO_HTTP, NULL), 6);
    assert_int_equal(router_select(&r, "1.2.3.9", 80, PROTO_HTTP, NULL), -1);
    router_free(&r);
}
static void test_rule_geo_site_cn(void **s) {
    (void)s;
    router_t r; router_init(&r, "direct", 1);
    rule_t rule = {0}; rule.id=1; rule.priority=100; rule.enabled=1;
    strcpy(rule.geo_site, "cn"); rule.upstream_id=7;
    router_add_rule(&r, &rule);
    assert_int_equal(router_select(&r, "a.example.cn", 80, PROTO_HTTP, NULL), 7);
    assert_int_equal(router_select(&r, "a.example.com", 80, PROTO_HTTP, NULL), -1);
    router_free(&r);
}
static void test_rule_geo_empty_db_no_match(void **s) {
    (void)s;
    /* 空库红线：未知(-1)不许匹配任何 geo 条件，一律走默认(-1)，不许按!cn分流 */
    extern void geo_test_reset(void);
    geo_test_reset(); /* 测试钩子：清表+清DNS缓存，保证本用例真是空库（cmocka同进程串行，前序dat残留必须清） */
    geo_init();
    assert_int_equal(geo_db_loaded(), 0);
    router_t r; router_init(&r, "direct", 1);
    rule_t rule = {0}; rule.id=1; rule.priority=100; rule.enabled=1;
    strcpy(rule.geo_ip, "cn"); rule.upstream_id=5;
    router_add_rule(&r, &rule);
    rule_t rule2 = {0}; rule2.id=2; rule2.priority=100; rule2.enabled=1;
    strcpy(rule2.geo_ip, "!cn"); rule2.upstream_id=6;
    router_add_rule(&r, &rule2);
    rule_t rule3 = {0}; rule3.id=3; rule3.priority=100; rule3.enabled=1;
    strcpy(rule3.geo_site, "cn"); rule3.upstream_id=7;
    router_add_rule(&r, &rule3);
    rule_t rule4 = {0}; rule4.id=4; rule4.priority=100; rule4.enabled=1;
    strcpy(rule4.geo_site, "!cn"); rule4.upstream_id=8;
    router_add_rule(&r, &rule4);
    /* IP 字面量不碰 DNS：空库未知一律走默认 */
    assert_int_equal(router_select(&r, "1.2.3.9", 80, PROTO_HTTP, NULL), -1);
    assert_int_equal(router_select(&r, "8.8.8.8", 80, PROTO_HTTP, NULL), -1);
    /* 域名 geo_site 纯查表不碰 DNS：空库同样走默认 */
    router_t r2; router_init(&r2, "direct", 1);
    router_add_rule(&r2, &rule3);
    router_add_rule(&r2, &rule4);
    assert_int_equal(router_select(&r2, "www.baidu.com", 80, PROTO_HTTP, NULL), -1);
    router_free(&r2);
    router_free(&r);
    geo_free();
}
static void test_rule_geo_and_domain(void **s) {
    (void)s;
    router_t r; router_init(&r, "direct", 1);
    rule_t rule = {0}; rule.id=1; rule.priority=100; rule.enabled=1;
    strcpy(rule.domain_pattern, "*.example.cn"); strcpy(rule.geo_site, "cn"); rule.upstream_id=8;
    router_add_rule(&r, &rule);
    assert_int_equal(router_select(&r, "a.example.cn", 80, PROTO_HTTP, NULL), 8);
    assert_int_equal(router_select(&r, "b.other.cn", 80, PROTO_HTTP, NULL), -1);
    router_free(&r);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_domain_wildcard),
        cmocka_unit_test(test_cidr),
        cmocka_unit_test(test_select_priority),
        cmocka_unit_test(test_select_default),
        cmocka_unit_test(test_remove_rule),
        cmocka_unit_test_setup_teardown(test_rule_geo_ip_cn, geo_setup, geo_teardown),
        cmocka_unit_test_setup_teardown(test_rule_geo_ip_neg, geo_setup, geo_teardown),
        cmocka_unit_test_setup_teardown(test_rule_geo_site_cn, geo_setup, geo_teardown),
        cmocka_unit_test(test_rule_geo_empty_db_no_match),
        cmocka_unit_test_setup_teardown(test_rule_geo_and_domain, geo_setup, geo_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
