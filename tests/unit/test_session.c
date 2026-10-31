#include <cmocka.h>
#include <string.h>
#include <time.h>
#include "rybaproxy/session.h"

/* 回归：失败路径（400/407/431/502）发完响应就结束了会话语义，
 * 但 http_finish 只落库不结算 → DB 里 status 恒为 SESS_ACTIVE(0)、
 * error_code 恒 0、ended_at 恒 0，面板就永远显示"活跃"。
 * session_settle_http 负责把"仍 ACTIVE 的会话"按 HTTP 状态码定性。 */
static void test_settle_http_error_marks_error(void **state) {
    (void)state;
    session_t *s = session_create(NULL, PROTO_HTTP, "127.0.0.1");
    assert_non_null(s);
    assert_int_equal(s->status, SESS_ACTIVE);
    session_settle_http(s, 502);
    assert_int_equal(s->status, SESS_ERROR);
    assert_int_equal(s->error_code, 502);
    assert_true(s->ended_at > 0);
    assert_non_null(strstr(s->error_msg, "502"));
    session_destroy(s);
}

static void test_settle_http_ok_marks_done(void **state) {
    (void)state;
    session_t *s = session_create(NULL, PROTO_HTTP, "127.0.0.1");
    assert_non_null(s);
    session_settle_http(s, 200);
    assert_int_equal(s->status, SESS_DONE);
    assert_int_equal(s->error_code, 0);
    assert_true(s->ended_at > 0);
    session_destroy(s);
}

/* 已经结算过的会话（正常隧道关闭）不能被二次覆盖 */
static void test_settle_http_keeps_existing_status(void **state) {
    (void)state;
    session_t *s = session_create(NULL, PROTO_HTTP, "127.0.0.1");
    assert_non_null(s);
    session_finish(s, SESS_TIMEOUT, 0, NULL);
    time_t ended = s->ended_at;
    session_settle_http(s, 502);
    assert_int_equal(s->status, SESS_TIMEOUT);
    assert_int_equal(s->error_code, 0);
    assert_int_equal(s->ended_at, ended);
    session_destroy(s);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_settle_http_error_marks_error),
        cmocka_unit_test(test_settle_http_ok_marks_done),
        cmocka_unit_test(test_settle_http_keeps_existing_status),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
