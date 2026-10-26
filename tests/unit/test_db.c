#include <cmocka.h>
#include <event2/event.h>
#include "rybaproxy/db.h"
#include "rybaproxy/session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_db_roundtrip(void **state) {
    (void)state;
    char path[128];
    snprintf(path, sizeof path, "/tmp/ryba_db_test_%d.db", (int)getpid());
    /* cleanup */
    remove(path);
    char wal[160]; snprintf(wal,sizeof wal,"%s-wal",path); remove(wal);
    char shm[160]; snprintf(shm,sizeof shm,"%s-shm",path); remove(shm);

    assert_int_equal(db_init(path), 0);
    db_set_retention(90);
    db_start();

    struct event_base *base = event_base_new();
    session_t *s = session_create(base, PROTO_HTTP, "127.0.0.1");
    session_set_target(s, "example.com", 80);
    session_set_method(s, "GET");
    s->bytes_up = 12; s->bytes_down = 34;
    s->upstream_id = 0;
    session_finish(s, SESS_DONE, 0, NULL);
    db_enqueue_session(s, "direct");

    db_stop();
    session_destroy(s);
    event_base_free(base);

    /* reopen and count */
    /* db_stop closed handle; reopen via new init? Instead query file with sqlite not available in cmocka easily; use db_init again */
    assert_int_equal(db_init(path), 0);
    char buf[4096];
    assert_int_equal(db_get_recent_sessions(10, buf, sizeof buf), 0);
    /* should contain one session */
    assert_true(strstr(buf, "example.com") != NULL);
    db_stop();
    remove(path); remove(wal); remove(shm);
}

int main(void) {
    const struct CMUnitTest tests[] = { cmocka_unit_test(test_db_roundtrip) };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
