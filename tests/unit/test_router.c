#include <cmocka.h>
#include "rybaproxy/router.h"
#include "rybaproxy/db.h"
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
    /* geo 查询走 sqlite：先开临时库（不碰家目录） */
    char dbpath[256];
    snprintf(dbpath, sizeof dbpath, "/tmp/ryba_rgeo_%d.db", (int)getpid());
    remove(dbpath);
    if (db_init(dbpath) != 0) return -1;
    if (geo_load(g_dir) != 0) { db_stop(); return -1; }
    return 0;
}
static int geo_teardown(void **s) {
    (void)s;
    geo_free();
    db_stop();
    char dbpath[256];
    snprintf(dbpath, sizeof dbpath, "/tmp/ryba_rgeo_%d.db", (int)getpid());
    remove(dbpath);
    /* resolver 必须随 geo_free 复位为 NULL（否则跨用例残留 fake） */
    assert_null(geo_test_get_resolver());
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -rf %s", g_dir);
    (void)system(cmd);
    return 0;
}
/* 网络哨兵：geo_site 路径不许解析 DNS，被调用即失败 */
int must_not_resolve_netcheck(const char *host, char *ip_out, size_t ipsz) {
    (void)host; (void)ip_out; (void)ipsz;
    fail_msg("geo_site path must not touch DNS");
    return -1;
}
/* fake DNS 解析器（测试替身）：全程不碰真实网络 */
int ryba_test_fake_dns(const char *host, char *ip_out, size_t ipsz) {
    (void)host;
    snprintf(ip_out, ipsz, "%s", "1.2.3.9"); /* CN 表内 */
    return 0;
}
int ryba_test_fake_dns_noncn(const char *host, char *ip_out, size_t ipsz) {
    (void)host;
    snprintf(ip_out, ipsz, "%s", "9.9.9.9"); /* CN 表外 */
    return 0;
}
static int *g_count_ptr = NULL;
void ryba_test_dns_count_reset(int *p) { g_count_ptr = p; }
int ryba_test_fake_dns_count(const char *host, char *ip_out, size_t ipsz) {
    (void)host;
    if (g_count_ptr) (*g_count_ptr)++;
    snprintf(ip_out, ipsz, "%s", "1.2.3.9");
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
    /* 注入 fake DNS（1.2.3.9=CN 表内）：域名全走 mock，不碰真实网络 */
    extern int ryba_test_fake_dns(const char *host, char *ip_out, size_t ipsz);
    geo_set_resolver(ryba_test_fake_dns);
    assert_int_equal(router_select(&r, "any.example", 80, PROTO_HTTP, NULL), 5);
    geo_set_resolver(NULL);
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
    /* fake DNS 返回非 CN 公网 IP：!cn 条件命中，全程无真实网络 */
    extern int ryba_test_fake_dns_noncn(const char *host, char *ip_out, size_t ipsz);
    geo_set_resolver(ryba_test_fake_dns_noncn);
    assert_int_equal(router_select(&r, "any.example", 80, PROTO_HTTP, NULL), 6);
    geo_set_resolver(NULL);
    router_free(&r);
}
static void test_rule_geo_site_cn(void **s) {
    (void)s;
    /* 注意：geo_site 规则走 geo_site_is_cn 纯查表，必须零网络。
     * 若 DNS 出现则说明实现漏了网络调用（曾有 5s 延迟 bug），fail_msg 会抓现行。 */
    geo_set_resolver(must_not_resolve_netcheck);
    router_t r; router_init(&r, "direct", 1);
    rule_t rule = {0}; rule.id=1; rule.priority=100; rule.enabled=1;
    strcpy(rule.geo_site, "cn"); rule.upstream_id=7;
    router_add_rule(&r, &rule);
    assert_int_equal(router_select(&r, "a.example.cn", 80, PROTO_HTTP, NULL), 7);
    assert_int_equal(router_select(&r, "a.example.com", 80, PROTO_HTTP, NULL), -1);
    geo_set_resolver(NULL);
    router_free(&r);
}
/* geo_ip="lan"/"!lan"：内网地址可指定走任意上游。
 * 内网判定不查库不解析，IP 字面量必须零网络（哨兵 mock 锁住）。 */
static void test_rule_geo_lan(void **s) {
    (void)s;
    geo_set_resolver(must_not_resolve_netcheck);
    router_t r; router_init(&r, "direct", 1);
    rule_t rule = {0}; rule.id=1; rule.priority=100; rule.enabled=1;
    strcpy(rule.geo_ip, "lan"); rule.upstream_id=3;
    router_add_rule(&r, &rule);
    assert_int_equal(router_select(&r, "192.168.1.5", 80, PROTO_HTTP, NULL), 3);
    assert_int_equal(router_select(&r, "10.0.0.9", 80, PROTO_HTTP, NULL), 3);
    assert_int_equal(router_select(&r, "172.27.130.170", 80, PROTO_HTTP, NULL), 3);
    assert_int_equal(router_select(&r, "8.8.8.8", 80, PROTO_HTTP, NULL), -1);
    geo_set_resolver(NULL);
    router_free(&r);
}

static void test_rule_geo_not_lan(void **s) {
    (void)s;
    router_t r; router_init(&r, "direct", 1);
    rule_t rule = {0}; rule.id=1; rule.priority=100; rule.enabled=1;
    strcpy(rule.geo_ip, "!lan"); rule.upstream_id=4;
    router_add_rule(&r, &rule);
    assert_int_equal(router_select(&r, "8.8.8.8", 80, PROTO_HTTP, NULL), 4);
    assert_int_equal(router_select(&r, "192.168.1.5", 80, PROTO_HTTP, NULL), -1);
    /* 域名解析到公网 IP → !lan 命中，全程 mock */
    extern int ryba_test_fake_dns_noncn(const char *host, char *ip_out, size_t ipsz);
    geo_set_resolver(ryba_test_fake_dns_noncn);
    assert_int_equal(router_select(&r, "any.example", 80, PROTO_HTTP, NULL), 4);
    geo_set_resolver(NULL);
    router_free(&r);
}

/* 内网规则优先级高于 cn 规则：内网才能被指定去代理而不是 direct */
static void test_rule_geo_lan_beats_cn(void **s) {
    (void)s;
    router_t r; router_init(&r, "direct", 1);
    rule_t cn = {0}; cn.id=1; cn.priority=200; cn.enabled=1;
    strcpy(cn.geo_ip, "cn"); cn.upstream_id=1;      /* direct */
    router_add_rule(&r, &cn);
    rule_t lan = {0}; lan.id=2; lan.priority=900; lan.enabled=1;
    strcpy(lan.geo_ip, "lan"); lan.upstream_id=0;   /* proxy */
    router_add_rule(&r, &lan);
    assert_int_equal(router_select(&r, "192.168.1.5", 80, PROTO_HTTP, NULL), 0);
    /* 1.2.3.9 在测试库里是 CN 且是公网：只有 cn 规则命中 */
    assert_int_equal(router_select(&r, "1.2.3.9", 80, PROTO_HTTP, NULL), 1);
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
    /* 空库时即使注入必成功的 resolver 也不许被调用：直接未知走默认 */
    static int g_called = 0;
    extern int ryba_test_fake_dns_count(const char *host, char *ip_out, size_t ipsz);
    g_called = 0;
    ryba_test_dns_count_reset(&g_called);
    geo_set_resolver(ryba_test_fake_dns_count);
    assert_int_equal(router_select(&r, "any.example", 80, PROTO_HTTP, NULL), -1);
    assert_int_equal(g_called, 0);
    geo_set_resolver(NULL);
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
    geo_set_resolver(must_not_resolve_netcheck);
    router_t r; router_init(&r, "direct", 1);
    rule_t rule = {0}; rule.id=1; rule.priority=100; rule.enabled=1;
    strcpy(rule.domain_pattern, "*.example.cn"); strcpy(rule.geo_site, "cn"); rule.upstream_id=8;
    router_add_rule(&r, &rule);
    assert_int_equal(router_select(&r, "a.example.cn", 80, PROTO_HTTP, NULL), 8);
    assert_int_equal(router_select(&r, "b.other.cn", 80, PROTO_HTTP, NULL), -1);
    geo_set_resolver(NULL);
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
        cmocka_unit_test_setup_teardown(test_rule_geo_lan, geo_setup, geo_teardown),
        cmocka_unit_test_setup_teardown(test_rule_geo_not_lan, geo_setup, geo_teardown),
        cmocka_unit_test_setup_teardown(test_rule_geo_lan_beats_cn, geo_setup, geo_teardown),
        cmocka_unit_test(test_rule_geo_empty_db_no_match),
        cmocka_unit_test_setup_teardown(test_rule_geo_and_domain, geo_setup, geo_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
