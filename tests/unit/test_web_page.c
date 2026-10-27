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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_page_uses_real_apis),
        cmocka_unit_test(test_page_has_hooks),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
