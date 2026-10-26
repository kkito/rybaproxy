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

#endif
