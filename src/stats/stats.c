#include "rybaproxy/stats.h"

#include <stdatomic.h>

static _Atomic uint64_t g_sessions = 0;
static _Atomic uint64_t g_bytes_up = 0;
static _Atomic uint64_t g_bytes_down = 0;
static _Atomic uint64_t g_errors = 0;
static _Atomic uint64_t g_bad = 0;
static _Atomic uint64_t g_dropped = 0;

void stats_init(void) {
    atomic_store(&g_sessions, 0);
    atomic_store(&g_bytes_up, 0);
    atomic_store(&g_bytes_down, 0);
    atomic_store(&g_errors, 0);
    atomic_store(&g_bad, 0);
    atomic_store(&g_dropped, 0);
}

void stats_record_session(const session_t *s) {
    if (!s) return;
    atomic_fetch_add(&g_sessions, 1);
    atomic_fetch_add(&g_bytes_up, s->bytes_up);
    atomic_fetch_add(&g_bytes_down, s->bytes_down);
    if (s->status != 0) atomic_fetch_add(&g_errors, 1);
}

stats_snapshot_t stats_get(void) {
    stats_snapshot_t snap;
    snap.total_sessions = atomic_load(&g_sessions);
    snap.total_bytes_up = atomic_load(&g_bytes_up);
    snap.total_bytes_down = atomic_load(&g_bytes_down);
    snap.total_errors = atomic_load(&g_errors);
    snap.bad_requests = atomic_load(&g_bad);
    snap.dropped_events = atomic_load(&g_dropped);
    return snap;
}

void stats_inc_bad_requests(void) { atomic_fetch_add(&g_bad, 1); }
