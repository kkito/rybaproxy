#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rybaproxy/geo.h"
#include "rybaproxy/db.h"

/* 真实 wire 格式迷你 dat（手写 protobuf 编码）：
 * GeoIPList{ entry{ country_code:"CN", cidr{ ip:\x01\x02\x03\x00, prefix:24 } } }
 * GeoSiteList{ entry{ country_code:"CN", domain{ type:SUFFIX(2), value:"example.cn" } } } */

/* entry payload: 0x0A "CN" + 0x12 cidr{0x0A len ip, 0x10 24} */
static const unsigned char kIpEntry[] = {
    0x0A, 0x02, 'C', 'N',
    0x12, 0x08,
      0x0A, 0x04, 1, 2, 3, 0,
      0x10, 0x18,
};
/* entry payload: 0x0A "CN" + 0x12 domain{0x08 02, 0x12 len "example.cn"} */
static const unsigned char kSiteEntry[] = {
    0x0A, 0x02, 'C', 'N',
    0x12, 0x0E,
      0x08, 0x02,
      0x12, 0x0A, 'e','x','a','m','p','l','e','.','c','n',
};

static char g_dir[128];

static void write_dat(const char *name, const unsigned char *entry, size_t elen) {
    char path[256];
    snprintf(path, sizeof path, "%s/%s", g_dir, name);
    FILE *f = fopen(path, "wb");
    assert_non_null(f);
    /* 顶层 GeoIPList/GeoSiteList { entry=0x0A LEN } */
    unsigned char hdr[2] = { 0x0A, (unsigned char)elen };
    assert_true(fwrite(hdr, 1, 2, f) == 2);
    assert_true(fwrite(entry, 1, elen, f) == elen);
    fclose(f);
}

static int setup(void **s) {
    (void)s;
    snprintf(g_dir, sizeof g_dir, "/tmp/ryba_geo_%d", (int)getpid());
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -rf %s && mkdir -p %s", g_dir, g_dir);
    assert_int_equal(system(cmd), 0);
    /* geo 查询走 sqlite：每个用例先开临时库（不碰家目录） */
    char dbpath[256];
    snprintf(dbpath, sizeof dbpath, "/tmp/ryba_geo_%d.db", (int)getpid());
    remove(dbpath);
    assert_int_equal(db_init(dbpath), 0);
    geo_init();
    return 0;
}

static int teardown(void **s) {
    (void)s;
    geo_free();
    db_stop();
    char dbpath[256];
    snprintf(dbpath, sizeof dbpath, "/tmp/ryba_geo_%d.db", (int)getpid());
    remove(dbpath);
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -rf %s", g_dir);
    (void)system(cmd);
    return 0;
}

static void test_private_is_cn(void **s) {
    (void)s;
    assert_int_equal(geo_ip_is_cn("192.168.1.1"), 1);
    assert_int_equal(geo_ip_is_cn("10.0.0.5"), 1);
    assert_int_equal(geo_ip_is_cn("172.16.9.9"), 1);
    assert_int_equal(geo_ip_is_cn("127.0.0.1"), 1);
    assert_int_equal(geo_ip_is_cn("::1"), 1);
}

static void test_invalid_input(void **s) {
    (void)s;
    assert_int_equal(geo_ip_is_cn(NULL), -1);
    assert_int_equal(geo_ip_is_cn("not-an-ip"), -1);
    assert_int_equal(geo_site_is_cn(NULL), -1);
    assert_int_equal(geo_site_is_cn(""), -1);
}

/* fake DNS 解析器：计数 + 可控返回，不碰真实网络 */
static int g_resolve_calls = 0;
static int fake_resolver(const char *host, char *ip_out, size_t ipsz) {
    (void)host;
    g_resolve_calls++;
    snprintf(ip_out, ipsz, "%s", "1.2.3.9");
    return 0;
}

/* 必失败的 resolver 替身：被调用即测试失败（fail_msg），证明零网络 */
static int must_not_resolve(const char *host, char *ip_out, size_t ipsz) {
    (void)host; (void)ip_out; (void)ipsz;
    fail_msg("resolver must not be called (no network in tests)");
    return -1;
}

static void test_host_no_dns_when_db_unloaded(void **s) {
    (void)s;
    /* 空库时 geo_host_is_cn 必须直接报未知，不许发起 DNS */
    geo_set_resolver(must_not_resolve);
    assert_int_equal(geo_db_loaded(), 0);
    assert_int_equal(geo_host_is_cn("www.baidu.com"), -1);
    geo_set_resolver(NULL);
}

static void test_host_uses_injected_resolver(void **s) {
    (void)s;
    /* 有库 + 注入 resolver：走 fake 结果，不碰真实 DNS */
    write_dat("geoip.dat", kIpEntry, sizeof kIpEntry);
    write_dat("geosite.dat", kSiteEntry, sizeof kSiteEntry);
    assert_int_equal(geo_load(g_dir), 0);
    geo_set_resolver(fake_resolver);
    g_resolve_calls = 0;
    assert_int_equal(geo_host_is_cn("anything.example"), 1); /* fake -> 1.2.3.9 -> CN */
    assert_int_equal(g_resolve_calls, 1);
    geo_set_resolver(NULL);
}

static void test_db_unloaded(void **s) {
    (void)s;
    /* 空库必须报未知(-1)，不许撒谎报非CN(0)：baidu 误判根因 */
    /* 即使注入 resolver 也不许被调用：空库直接未知 */
    geo_set_resolver(must_not_resolve);
    assert_int_equal(geo_db_loaded(), 0);
    assert_int_equal(geo_ip_is_cn("8.8.8.8"), -1);
    assert_int_equal(geo_ip_is_cn("110.242.69.21"), -1);
    assert_int_equal(geo_site_is_cn("www.baidu.com"), -1);
    assert_int_equal(geo_host_is_cn("www.baidu.com"), -1);
    /* 私网不依赖 dat，仍判 CN */
    assert_int_equal(geo_ip_is_cn("192.168.1.1"), 1);
    geo_set_resolver(NULL);
}

static void test_load_wire_dat(void **s) {
    (void)s;
    write_dat("geoip.dat", kIpEntry, sizeof kIpEntry);
    write_dat("geosite.dat", kSiteEntry, sizeof kSiteEntry);
    assert_int_equal(geo_load(g_dir), 0);
    assert_true(geo_db_loaded());
    assert_true(geo_ip_count() == 1);
    assert_true(geo_site_count() == 1);
    assert_int_equal(geo_ip_is_cn("1.2.3.9"), 1);
    assert_int_equal(geo_ip_is_cn("9.9.9.9"), 0);
    assert_int_equal(geo_site_is_cn("a.example.cn"), 1);
    assert_int_equal(geo_site_is_cn("example.cn"), 1);
    assert_int_equal(geo_site_is_cn("notexample.cn"), 0);
    assert_int_equal(geo_site_is_cn("example.com"), 0);
    /* IP 字面量走 geo_host 直查，不碰 DNS */
    geo_set_resolver(must_not_resolve);
    assert_int_equal(geo_host_is_cn("1.2.3.9"), 1);
    assert_int_equal(geo_host_is_cn("9.9.9.9"), 0);
    geo_set_resolver(NULL);
}

static void test_load_missing_dir(void **s) {
    (void)s;
    assert_int_equal(geo_load("/tmp/ryba_geo_no_such_dir_xyz"), -1);
}

static void test_resolve_dir_prefers_cfg(void **s) {
    (void)s;
    /* cfg 优先级最高，db_dir 仅在前两者为空时作为回退 */
    char out[256];
    assert_int_equal(geo_resolve_dir("/cfg/dir", "/env/dir", "/home/u", out, sizeof out), 0);
    assert_string_equal(out, "/cfg/dir");
    assert_int_equal(geo_resolve_dir("", "/env/dir", "/home/u", out, sizeof out), 0);
    assert_string_equal(out, "/env/dir");
}

static void test_resolve_dir_env_then_home_default(void **s) {
    (void)s;
    char out[256];
    assert_int_equal(geo_resolve_dir(NULL, "/env/dir", "/home/u", out, sizeof out), 0);
    assert_string_equal(out, "/env/dir");
    assert_int_equal(geo_resolve_dir("", "", "/home/u", out, sizeof out), 0);
    assert_string_equal(out, "/home/u/.local/rybaproxy");
}

static void test_resolve_dir_no_home_falls_back_dot(void **s) {
    (void)s;
    char out[256];
    assert_int_equal(geo_resolve_dir(NULL, NULL, NULL, out, sizeof out), 0);
    assert_string_equal(out, ".");
    assert_int_equal(geo_resolve_dir(NULL, NULL, NULL, NULL, 0), -1);
}

static void test_reload_replaces_without_dup(void **s) {
    (void)s;
    /* 同一目录连 load 两次：第二次先清空再装，计数不变 */
    write_dat("geoip.dat", kIpEntry, sizeof kIpEntry);
    write_dat("geosite.dat", kSiteEntry, sizeof kSiteEntry);
    assert_int_equal(geo_load(g_dir), 0);
    size_t ip1 = geo_ip_count(), site1 = geo_site_count();
    assert_true(ip1 == 1 && site1 >= 1);
    assert_int_equal(geo_load(g_dir), 0);
    assert_int_equal(geo_ip_count(), ip1);
    assert_int_equal(geo_site_count(), site1);
}

/* RED(Task3): 导入后删掉 dat，查询仍命中 → 证明走 sqlite 不依赖 dat 文件 */
static void test_import_then_query_from_sqlite(void **s) {
    (void)s;
    write_dat("geoip.dat", kIpEntry, sizeof kIpEntry);
    write_dat("geosite.dat", kSiteEntry, sizeof kSiteEntry);
    assert_int_equal(geo_load(g_dir), 0);
    assert_true(geo_db_loaded());
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -f %s/*.dat", g_dir);
    assert_int_equal(system(cmd), 0);
    assert_int_equal(geo_ip_is_cn("1.2.3.9"), 1);
    assert_int_equal(geo_ip_is_cn("9.9.9.9"), 0);
    assert_int_equal(geo_site_is_cn("a.example.cn"), 1);
    assert_int_equal(geo_site_is_cn("example.com"), 0);
}

int main(void) {
    const struct CMUnitTest t[] = {
        cmocka_unit_test_setup_teardown(test_private_is_cn, setup, teardown),
        cmocka_unit_test_setup_teardown(test_invalid_input, setup, teardown),
        cmocka_unit_test_setup_teardown(test_db_unloaded, setup, teardown),
        cmocka_unit_test_setup_teardown(test_load_wire_dat, setup, teardown),
        cmocka_unit_test_setup_teardown(test_host_no_dns_when_db_unloaded, setup, teardown),
        cmocka_unit_test_setup_teardown(test_host_uses_injected_resolver, setup, teardown),
        cmocka_unit_test_setup_teardown(test_load_missing_dir, setup, teardown),
        cmocka_unit_test(test_resolve_dir_prefers_cfg),
        cmocka_unit_test(test_resolve_dir_env_then_home_default),
        cmocka_unit_test(test_resolve_dir_no_home_falls_back_dot),
        cmocka_unit_test_setup_teardown(test_reload_replaces_without_dup, setup, teardown),
        cmocka_unit_test_setup_teardown(test_import_then_query_from_sqlite, setup, teardown),
    };
    return cmocka_run_group_tests(t, NULL, NULL);
}
