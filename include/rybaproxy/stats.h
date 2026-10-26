#ifndef RYBAPROXY_STATS_H
#define RYBAPROXY_STATS_H

#include "rybaproxy/session.h"
#include <stdint.h>

typedef struct {
    uint64_t total_sessions;
    uint64_t total_bytes_up;
    uint64_t total_bytes_down;
    uint64_t total_errors;
    uint64_t bad_requests;
    uint64_t dropped_events;
} stats_snapshot_t;

void stats_init(void);
void stats_record_session(const session_t *s);
stats_snapshot_t stats_get(void);
void stats_inc_bad_requests(void);
void stats_inc_dropped_events(void);

#endif
