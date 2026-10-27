#ifndef RYBAPROXY_DB_H
#define RYBAPROXY_DB_H

#include "rybaproxy/session.h"

int db_init(const char *path);
void db_set_retention(int days);
void db_start(void);
void db_stop(void);
int db_enqueue_session(const session_t *s, const char *upstream_name);
void db_retention(int days);
int db_get_recent_sessions(int limit, char *buf, size_t bufsz);
int db_query_sessions(const char *client, const char *target, int upstream_id, int limit, int offset, char *buf, size_t bufsz, int *out_total);
int db_get_session_by_id(long long id, char *buf, size_t bufsz);
int db_stats_summary(long long from_ms, long long to_ms, char *buf, size_t bufsz);
int db_stats_daily(int days, char *buf, size_t bufsz);
int db_stats_top(const char *by, int limit, long long from_ms, long long to_ms, char *buf, size_t bufsz);
int db_settings_get(char *buf, size_t bufsz);
int db_settings_set(const char *key, const char *value);

#endif
