/* strcasestr 是 glibc 的 GNU 扩展，macOS/BSD 头文件里也顺带暴露，
 * 导致本地怎么编都过、CI(Linux 严格 -std=c11) 才炸。用自研纯函数替代，
 * 顺带把大小写不敏感子串查找变成可测的逻辑。 */
#include <cmocka.h>
#include <string.h>

#include "rybaproxy/strutil.h"

static void test_case_find_basic(void **s) {
    (void)s;
    assert_string_equal(str_case_find("Proxy-Authorization: Basic x", "proxy-authorization:"), "Proxy-Authorization: Basic x");
    assert_string_equal(str_case_find("xxHOST: a", "host:"), "HOST: a");
}

static void test_case_find_absent(void **s) {
    (void)s;
    assert_null(str_case_find("Content-Length: 5", "authorization"));
}

static void test_case_find_edges(void **s) {
    (void)s;
    /* 空 needle / 空 haystack：语义与 strstr 一致，返回 haystack 本身 */
    assert_string_equal(str_case_find("abc", ""), "abc");
    assert_null(str_case_find("", "abc"));
    assert_null(str_case_find(NULL, "a"));
    assert_null(str_case_find("abc", NULL));
    /* needle 比 haystack 长 */
    assert_null(str_case_find("ab", "abc"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_case_find_basic),
        cmocka_unit_test(test_case_find_absent),
        cmocka_unit_test(test_case_find_edges),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
