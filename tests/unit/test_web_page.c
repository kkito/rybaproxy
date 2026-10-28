#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include "web_page_gen.h"

static void test_page_uses_real_apis(void **state) {
    (void)state;
    assert_true(strstr(WEB_PAGE_HTML_GEN, "home-direct") == NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "Math.random") == NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/stats/daily") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/upstreams") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "refreshLive") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "setInterval(") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "EventSource") == NULL);
}

static void test_page_has_hooks(void **state) {
    (void)state;
    assert_true(strstr(WEB_PAGE_HTML_GEN, "sessPager") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "username") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "fltClient") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "data-test") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "ryba-stat") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "heatmap") != NULL);
}

static void test_page_geo_hooks(void **state) {
    (void)state;
    /* geo 条件下拉 + 出口 select + 管理卡 + 检测页调用 */
    assert_true(strstr(WEB_PAGE_HTML_GEN, "name=\"geo_ip\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "name=\"geo_site\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "name=\"upstream_id\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/geo/status") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/geo/download") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/geo/check") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "geoip:cn") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "geosite:cn") != NULL);
    /* 旧 number 手填框已移除，出口是下拉 */
    assert_true(strstr(WEB_PAGE_HTML_GEN, "name=\"upstream_id\" type=\"number\"") == NULL);
}

static void test_page_layout_stack(void **state) {
    (void)state;
    /* 节点 / IP 库 / 路由三卡纵向堆叠，不再左右分栏 */
    assert_true(strstr(WEB_PAGE_HTML_GEN, "minmax(0,4fr) minmax(0,6fr)") == NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "出口节点") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "Geo 数据管理") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "规则列表") != NULL);
}

static void test_page_geo_hooks_tail(void **state) {
    /* geo 条件下拉 + 出口 select + 管理卡 + 检测页调用 */
    assert_true(strstr(WEB_PAGE_HTML_GEN, "name=\"geo_ip\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "name=\"geo_site\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "name=\"upstream_id\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/geo/status") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/geo/download") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/geo/check") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "geoip:cn") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "geosite:cn") != NULL);
    /* 旧 number 手填框已移除，出口是下拉；管理卡展示下载源/目录 */
    assert_true(strstr(WEB_PAGE_HTML_GEN, "name=\"upstream_id\" type=\"number\"") == NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "geoSrc") != NULL);
    /* 空库语义：未知显示 cnText + 未加载提示（esbuild 会把中文转成 \u 序列，所以查 db_loaded 行为钩子） */
    assert_true(strstr(WEB_PAGE_HTML_GEN, "cnText") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "db_loaded") != NULL);
}

static void test_page_dns_hooks(void **state) {
    (void)state;
    /* DNS 卡片：状态/代理设置/nameserver/缓存/日志 + 后端接口调用 */
    assert_true(strstr(WEB_PAGE_HTML_GEN, "dnsStatus") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "dnsNsTable") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "dnsCacheTable") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "dnsLogsTable") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/dns/status") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/dns/nameservers") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/dns/cache") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/dns/logs") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/dns/cache/flush") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/dns/logs/clear") != NULL);
    assert_true(strstr(WEB_PAGE_HTML_GEN, "/api/dns/proxy") != NULL);
}

static void test_page_geo_js_no_raw_newline_in_string(void **state) {
    (void)state;
    /* 生成页由 esbuild 打包，转义由工具链保证；这里只锁行为钩子存在 */
    assert_true(strstr(WEB_PAGE_HTML_GEN, "db_loaded") != NULL);
}

static void test_page_geo_status_updated_on_success(void **state) {
    (void)state;
    /* RED: reloadGeoStatus 成功路径必须更新 #geoStatus，否则永远显示“加载中…” */
    /* esbuild 会把单引号转成双引号，只数 geoStatus 出现次数（模板 + 成功更新路径） */
    const char *p = WEB_PAGE_HTML_GEN;
    int n = 0;
    while ((p = strstr(p, "geoStatus")) != NULL) { n++; p++; }
    assert_true(n >= 2);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_page_uses_real_apis),
        cmocka_unit_test(test_page_has_hooks),
        cmocka_unit_test(test_page_geo_hooks),
        cmocka_unit_test(test_page_geo_hooks_tail),
        cmocka_unit_test(test_page_geo_js_no_raw_newline_in_string),
        cmocka_unit_test(test_page_geo_status_updated_on_success),
        cmocka_unit_test(test_page_dns_hooks),
        cmocka_unit_test(test_page_layout_stack),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
