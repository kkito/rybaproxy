#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rybaproxy/geo.h"

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
    geo_init();
    return 0;
}

static int teardown(void **s) {
    (void)s;
    geo_free();
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

static void test_db_unloaded(void **s) {
    (void)s;
    assert_int_equal(geo_db_loaded(), 0);
    assert_int_equal(geo_ip_is_cn("8.8.8.8"), 0); /* 无 dat：未知按非CN */
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
    assert_int_equal(geo_host_is_cn("1.2.3.9"), 1);
    assert_int_equal(geo_host_is_cn("9.9.9.9"), 0);
}

static void test_load_missing_dir(void **s) {
    (void)s;
    assert_int_equal(geo_load("/tmp/ryba_geo_no_such_dir_xyz"), -1);
}

int main(void) {
    const struct CMUnitTest t[] = {
        cmocka_unit_test_setup_teardown(test_private_is_cn, setup, teardown),
        cmocka_unit_test_setup_teardown(test_invalid_input, setup, teardown),
        cmocka_unit_test_setup_teardown(test_db_unloaded, setup, teardown),
        cmocka_unit_test_setup_teardown(test_load_wire_dat, setup, teardown),
        cmocka_unit_test_setup_teardown(test_load_missing_dir, setup, teardown),
    };
    return cmocka_run_group_tests(t, NULL, NULL);
}
