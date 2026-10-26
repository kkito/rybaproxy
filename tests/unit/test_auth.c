#include <cmocka.h>
#include "rybaproxy/auth.h"
#include <string.h>

static void test_basic_ok(void **state) {
    (void)state;
    /* "dXNlcjpwYXNz" = user:pass */
    assert_true(auth_basic_check("Basic dXNlcjpwYXNz", "user", "pass"));
    assert_false(auth_basic_check("Basic dXNlcjpwYXNz", "user", "wrong"));
    assert_false(auth_basic_check("Basic xxx", "user", "pass"));
}

static void test_base64(void **state) {
    (void)state;
    unsigned char out[64];
    int n = base64_decode("dXNlcjpwYXNz", out, sizeof out);
    assert_int_equal(n, 9);
    out[n] = '\0';
    assert_string_equal((char*)out, "user:pass");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_basic_ok),
        cmocka_unit_test(test_base64),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
