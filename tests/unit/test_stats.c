#include <cmocka.h>
#include "rybaproxy/stats.h"
#include "rybaproxy/session.h"
#include <event2/event.h>

static void test_counter(void **state) {
    (void)state;
    stats_init();
    struct event_base *base = event_base_new();
    session_t *s = session_create(base, PROTO_HTTP, "127.0.0.1");
    s->bytes_up = 10; s->bytes_down = 20;
    session_finish(s, SESS_DONE, 0, NULL);
    stats_record_session(s);
    stats_snapshot_t snap = stats_get();
    assert_int_equal(snap.total_sessions, 1);
    assert_int_equal(snap.total_bytes_up, 10);
    assert_int_equal(snap.total_bytes_down, 20);
    session_destroy(s);
    event_base_free(base);
}

int main(void) {
    const struct CMUnitTest tests[] = { cmocka_unit_test(test_counter) };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
