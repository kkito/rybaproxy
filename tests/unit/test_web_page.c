#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include "web_page.h"

static void test_page_uses_real_apis(void **state) {
    (void)state;
    assert_true(strstr(WEB_PAGE_HTML, "home-direct") == NULL);
    assert_true(strstr(WEB_PAGE_HTML, "Math.random") == NULL);
    assert_true(strstr(WEB_PAGE_HTML, "/api/stats/daily") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "/api/upstreams") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "setInterval(refreshLive, 5000)") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "EventSource") == NULL);
}

static void test_page_has_hooks(void **state) {
    (void)state;
    assert_true(strstr(WEB_PAGE_HTML, "sessPager") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "username") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "fltClient") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "data-test") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "ryba-stat") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "heatmap") != NULL);
}

static void test_page_geo_hooks(void **state) {
    (void)state;
    /* geo 条件下拉 + 出口 select + 管理卡 + 检测页调用 */
    assert_true(strstr(WEB_PAGE_HTML, "name=\"geo_ip\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "name=\"geo_site\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "name=\"upstream_id\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "/api/geo/status") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "/api/geo/download") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "/api/geo/check") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "geoip:cn") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "geosite:cn") != NULL);
    /* 旧 number 手填框已移除，出口是下拉 */
    assert_true(strstr(WEB_PAGE_HTML, "name=\"upstream_id\" type=\"number\"") == NULL);
}

static void test_page_layout_stack(void **state) {
    (void)state;
    /* 节点 / IP 库 / 路由三卡纵向堆叠，不再左右分栏 */
    assert_true(strstr(WEB_PAGE_HTML, "minmax(0,4fr) minmax(0,6fr)") == NULL);
    assert_true(strstr(WEB_PAGE_HTML, "出口节点") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "Geo 数据管理") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "规则列表") != NULL);
}

static void test_page_geo_hooks_tail(void **state) {
    /* geo 条件下拉 + 出口 select + 管理卡 + 检测页调用 */
    assert_true(strstr(WEB_PAGE_HTML, "name=\"geo_ip\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "name=\"geo_site\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "name=\"upstream_id\"") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "/api/geo/status") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "/api/geo/download") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "/api/geo/check") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "geoip:cn") != NULL);
    assert_true(strstr(WEB_PAGE_HTML, "geosite:cn") != NULL);
    /* 旧 number 手填框已移除，出口是下拉 */
    assert_true(strstr(WEB_PAGE_HTML, "name=\"upstream_id\" type=\"number\"") == NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_page_uses_real_apis),
        cmocka_unit_test(test_page_has_hooks),
        cmocka_unit_test(test_page_geo_hooks),
        cmocka_unit_test(test_page_layout_stack),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
