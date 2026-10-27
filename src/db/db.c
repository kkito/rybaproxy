#include "rybaproxy/db.h"
#include "rybaproxy/paths.h"
#include "rybaproxy/router.h"
#include "rybaproxy/stats.h"
#include "rybaproxy/upstream.h"

#include <sqlite3.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define DB_QUEUE_CAP 65536
#define DB_BATCH 256

typedef struct node {
    session_t snap;
    char upstream_name[128];
    struct node *next;
} node_t;

static sqlite3 *g_db = NULL;
static sqlite3_stmt *g_stmt = NULL;

static pthread_t g_thread;
static int g_running = 0;
static int g_shutdown = 0;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static node_t *g_head = NULL;
static node_t *g_tail = NULL;
static size_t g_count = 0;

static int g_retention_days = 90;

static const char *SCHEMA =
"CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);"
"CREATE TABLE IF NOT EXISTS upstream_profiles ("
" id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, type TEXT NOT NULL,"
" host TEXT, port INTEGER, username TEXT, password TEXT, enabled INTEGER NOT NULL DEFAULT 1,"
" created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
"CREATE TABLE IF NOT EXISTS rules ("
" id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, priority INTEGER NOT NULL DEFAULT 100,"
" enabled INTEGER NOT NULL DEFAULT 1, domain_pattern TEXT, ip_cidr TEXT, port INTEGER DEFAULT 0,"
" protocol TEXT DEFAULT 'any', upstream_id INTEGER NOT NULL, geo_ip TEXT DEFAULT '', geo_site TEXT DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);";
static const char *RULES_MIGRATIONS[] = {
"ALTER TABLE rules ADD COLUMN geo_ip TEXT DEFAULT '';",
"ALTER TABLE rules ADD COLUMN geo_site TEXT DEFAULT '';",
};
static const char *SCHEMA_TAIL =
"CREATE TABLE IF NOT EXISTS sessions ("
" id INTEGER PRIMARY KEY, protocol TEXT NOT NULL, client_ip TEXT NOT NULL, target_host TEXT NOT NULL,"
" target_port INTEGER NOT NULL, method TEXT, upstream_id INTEGER, upstream_name TEXT, status INTEGER NOT NULL,"
" error_code INTEGER, error_msg TEXT, bytes_up INTEGER NOT NULL, bytes_down INTEGER NOT NULL,"
" started_at INTEGER NOT NULL, ended_at INTEGER NOT NULL, duration_ms INTEGER NOT NULL, nginx_forwarded INTEGER NOT NULL DEFAULT 0);"
"CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);"
"CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);";

static void mkdirp(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static char g_db_path[512] = "";

int db_get_dir(char *out, size_t outsz) {
    if (!out || !outsz) return -1;
    const char *p = g_db_path[0] ? g_db_path : "./stats.db";
    snprintf(out, outsz, "%s", p);
    char *slash = strrchr(out, '/');
    if (slash) *slash = '\0';
    else snprintf(out, outsz, ".");
    return 0;
}

int db_init(const char *path) {
    if (!path || !path[0]) {
        ryba_default_db_path(getenv("HOME"), g_db_path, sizeof g_db_path);
        path = g_db_path;
    } else {
        snprintf(g_db_path, sizeof g_db_path, "%s", path);
    }
    /* ensure parent dir */
    char dir[512];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) { *slash = '\0'; mkdirp(dir); }

    if (sqlite3_open(path, &g_db) != SQLITE_OK || sqlite3_exec(g_db, "SELECT 1;", NULL, NULL, NULL) != SQLITE_OK) {
        if (g_db) sqlite3_close(g_db);
        g_db = NULL;
        if (sqlite3_open("./stats.db", &g_db) != SQLITE_OK) {
            fprintf(stderr, "db open failed: %s\n", sqlite3_errmsg(g_db));
            return -1;
        }
    }
    sqlite3_busy_timeout(g_db, 5000);
    char *err = NULL;
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, &err);
    sqlite3_exec(g_db, SCHEMA, NULL, NULL, &err);
    sqlite3_exec(g_db, SCHEMA_TAIL, NULL, NULL, &err);
    if (err) { sqlite3_free(err); err = NULL; }
    /* 历史库补列：geo_ip/geo_site（新库 SCHEMA 已含，只对老库生效） */
    for (size_t i = 0; i < sizeof RULES_MIGRATIONS / sizeof RULES_MIGRATIONS[0]; i++) {
        char *merr = NULL;
        sqlite3_exec(g_db, RULES_MIGRATIONS[i], NULL, NULL, &merr);
        if (merr) sqlite3_free(merr); /* duplicate column 等可忽略 */
    }
    /* schema version */
    sqlite3_exec(g_db, "INSERT INTO schema_version(version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);", NULL, NULL, NULL);

    const char *sql = "INSERT INTO sessions(protocol,client_ip,target_host,target_port,method,upstream_id,upstream_name,status,error_code,error_msg,bytes_up,bytes_down,started_at,ended_at,duration_ms,nginx_forwarded) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
    /* we insert id explicitly too; adjust: include id */
    sql = "INSERT INTO sessions(id,protocol,client_ip,target_host,target_port,method,upstream_id,upstream_name,status,error_code,error_msg,bytes_up,bytes_down,started_at,ended_at,duration_ms,nginx_forwarded) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
    if (sqlite3_prepare_v2(g_db, sql, -1, &g_stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare failed: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }
    return 0;
}

void db_retention(int days) {
    if (!g_db) return;
    if (days <= 0) days = 90;
    time_t now = time(NULL);
    time_t cutoff = now - (time_t)days * 86400;
    char sql[256];
    snprintf(sql, sizeof sql, "DELETE FROM sessions WHERE started_at < %ld;", (long)cutoff);
    sqlite3_exec(g_db, sql, NULL, NULL, NULL);
    snprintf(sql, sizeof sql, "DELETE FROM http_requests WHERE started_at < %ld;", (long)cutoff);
    sqlite3_exec(g_db, sql, NULL, NULL, NULL);
}

static void insert_node(node_t *n) {
    if (!g_db || !g_stmt) return;
    sqlite3_reset(g_stmt);
    sqlite3_bind_int64(g_stmt, 1, (sqlite3_int64)n->snap.id);
    sqlite3_bind_text(g_stmt, 2, n->snap.protocol == PROTO_HTTP ? "http" : "socks5", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_stmt, 3, n->snap.client_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_stmt, 4, n->snap.target_host, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_stmt, 5, n->snap.target_port);
    sqlite3_bind_text(g_stmt, 6, n->snap.method, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_stmt, 7, n->snap.upstream_id);
    sqlite3_bind_text(g_stmt, 8, n->upstream_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_stmt, 9, (int)n->snap.status);
    sqlite3_bind_int(g_stmt, 10, n->snap.error_code);
    sqlite3_bind_text(g_stmt, 11, n->snap.error_msg, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(g_stmt, 12, (sqlite3_int64)n->snap.bytes_up);
    sqlite3_bind_int64(g_stmt, 13, (sqlite3_int64)n->snap.bytes_down);
    sqlite3_bind_int64(g_stmt, 14, (sqlite3_int64)n->snap.started_at);
    sqlite3_bind_int64(g_stmt, 15, (sqlite3_int64)n->snap.ended_at);
    long dur = (n->snap.ended_at > n->snap.started_at) ? (n->snap.ended_at - n->snap.started_at) * 1000 : 0;
    sqlite3_bind_int64(g_stmt, 16, dur);
    sqlite3_bind_int(g_stmt, 17, 0);
    sqlite3_step(g_stmt);
}

static void *writer_main(void *arg) {
    (void)arg;
    time_t last_ret = time(NULL);
    while (1) {
        pthread_mutex_lock(&g_lock);
        while (g_head == NULL && !g_shutdown) {
            pthread_cond_wait(&g_cond, &g_lock);
        }
        /* collect batch */
        node_t *batch[DB_BATCH];
        int bn = 0;
        while (g_head && bn < DB_BATCH) {
            node_t *n = g_head;
            g_head = n->next;
            if (!g_head) g_tail = NULL;
            g_count--;
            batch[bn++] = n;
        }
        int shutdown = g_shutdown && g_head == NULL && bn == 0;
        pthread_mutex_unlock(&g_lock);

        if (bn > 0) {
            sqlite3_exec(g_db, "BEGIN;", NULL, NULL, NULL);
            for (int i = 0; i < bn; i++) insert_node(batch[i]);
            sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);
            for (int i = 0; i < bn; i++) free(batch[i]);
        }

        /* retention daily */
        time_t now = time(NULL);
        if (now - last_ret > 86400) {
            db_retention(g_retention_days);
            last_ret = now;
        }

        if (shutdown) break;
        if (g_shutdown && g_head == NULL) {
            /* drain remaining handled by loop; exit when no more */
            pthread_mutex_lock(&g_lock);
            if (g_head == NULL) { pthread_mutex_unlock(&g_lock); break; }
            pthread_mutex_unlock(&g_lock);
        }
    }
    return NULL;
}

int db_enqueue_session(const session_t *s, const char *upstream_name) {
    if (!s) return -1;
    pthread_mutex_lock(&g_lock);
    if (g_count >= DB_QUEUE_CAP) {
        pthread_mutex_unlock(&g_lock);
        stats_inc_dropped_events();
        return -1;
    }
    node_t *n = calloc(1, sizeof *n);
    n->snap = *s;
    if (upstream_name) snprintf(n->upstream_name, sizeof n->upstream_name, "%s", upstream_name);
    else strcpy(n->upstream_name, "direct");
    if (!g_tail) g_head = g_tail = n;
    else { g_tail->next = n; g_tail = n; }
    g_count++;
    pthread_cond_signal(&g_cond);
    pthread_mutex_unlock(&g_lock);
    return 0;
}

void db_set_retention(int days){ if(days>0) g_retention_days=days; }
void db_start(void) {
    g_shutdown = 0;
    g_running = 1;
    pthread_create(&g_thread, NULL, writer_main, NULL);
}

void db_stop(void) {
    if (!g_running) return;
    pthread_mutex_lock(&g_lock);
    g_shutdown = 1;
    pthread_cond_broadcast(&g_cond);
    pthread_mutex_unlock(&g_lock);
    pthread_join(g_thread, NULL);
    g_running = 0;
    if (g_stmt) { sqlite3_finalize(g_stmt); g_stmt = NULL; }
    if (g_db) { sqlite3_close(g_db); g_db = NULL; }
}



/* ---------- helpers ---------- */
static void db_json_escape(const char *src, char *dst, size_t dstsz) {
    size_t j = 0;
    if (!src) src = "";
    for (size_t i = 0; src[i] && j + 2 < dstsz; i++) {
        char c = src[i];
        if (c == '"' || c == '\\') { dst[j++] = '\\'; dst[j++] = c; }
        else if (c == '\n') { dst[j++] = '\\'; dst[j++] = 'n'; }
        else if (c == '\r') { dst[j++] = '\\'; dst[j++] = 'r'; }
        else if ((unsigned char)c < 0x20) { dst[j++] = ' '; }
        else dst[j++] = c;
    }
    dst[j] = '\0';
}

int db_query_sessions(const char *client, const char *target, int upstream_id, int limit, int offset, char *buf, size_t bufsz, int *out_total) {
    if (!buf || bufsz == 0) return -1;
    if (limit <= 0) limit = 100;
    if (limit > 1000) limit = 1000;
    if (offset < 0) offset = 0;
    if (!g_db) { snprintf(buf, bufsz, "{\"data\":[],\"total\":0,\"limit\":%d,\"offset\":%d}", limit, offset); if (out_total) *out_total = 0; return 0; }
    char where[512]; where[0] = '\0';
    char cpat[140] = "", tpat[520] = "";
    if (client && client[0]) { snprintf(cpat, sizeof cpat, "%%%s%%", client); strncat(where, " AND client_ip LIKE ? ESCAPE '\\'", sizeof where - strlen(where) - 1); }
    if (target && target[0]) { snprintf(tpat, sizeof tpat, "%%%s%%", target); strncat(where, " AND target_host LIKE ? ESCAPE '\\'", sizeof where - strlen(where) - 1); }
    if (upstream_id >= 0) strncat(where, " AND upstream_id = ?", sizeof where - strlen(where) - 1);
    char csql[768];
    snprintf(csql, sizeof csql, "SELECT COUNT(*) FROM sessions WHERE 1=1%s;", where);
    sqlite3_stmt *st = NULL;
    int total = 0;
    if (sqlite3_prepare_v2(g_db, csql, -1, &st, NULL) == SQLITE_OK) {
        int bi = 1;
        if (cpat[0]) sqlite3_bind_text(st, bi++, cpat, -1, SQLITE_TRANSIENT);
        if (tpat[0]) sqlite3_bind_text(st, bi++, tpat, -1, SQLITE_TRANSIENT);
        if (upstream_id >= 0) sqlite3_bind_int(st, bi++, upstream_id);
        if (sqlite3_step(st) == SQLITE_ROW) total = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    if (out_total) *out_total = total;
    char qsql[768];
    snprintf(qsql, sizeof qsql, "SELECT id,protocol,client_ip,target_host,target_port,status,bytes_up,bytes_down,started_at,ended_at FROM sessions WHERE 1=1%s ORDER BY started_at DESC LIMIT ? OFFSET ?;", where);
    size_t pos = 0;
    pos += snprintf(buf + pos, bufsz - pos, "{\"data\":[");
    if (sqlite3_prepare_v2(g_db, qsql, -1, &st, NULL) != SQLITE_OK) {
        snprintf(buf, bufsz, "{\"data\":[],\"total\":%d,\"limit\":%d,\"offset\":%d}", total, limit, offset);
        return 0;
    }
    int bi = 1;
    if (cpat[0]) sqlite3_bind_text(st, bi++, cpat, -1, SQLITE_TRANSIENT);
    if (tpat[0]) sqlite3_bind_text(st, bi++, tpat, -1, SQLITE_TRANSIENT);
    if (upstream_id >= 0) sqlite3_bind_int(st, bi++, upstream_id);
    sqlite3_bind_int(st, bi++, limit);
    sqlite3_bind_int(st, bi++, offset);
    int first = 1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        char cipe[130], thoste[520];
        db_json_escape((const char*)sqlite3_column_text(st, 2), cipe, sizeof cipe);
        db_json_escape((const char*)sqlite3_column_text(st, 3), thoste, sizeof thoste);
        char item[1024];
        snprintf(item, sizeof item,
            "%s{\"id\":%lld,\"protocol\":\"%s\",\"client_ip\":\"%s\",\"target_host\":\"%s\",\"target_port\":%d,\"status\":%d,\"bytes_up\":%lld,\"bytes_down\":%lld,\"started_at\":%lld,\"ended_at\":%lld}",
            first ? "" : ",",
            (long long)sqlite3_column_int64(st, 0),
            (const char*)sqlite3_column_text(st, 1), cipe, thoste,
            sqlite3_column_int(st, 4), sqlite3_column_int(st, 5),
            (long long)sqlite3_column_int64(st, 6), (long long)sqlite3_column_int64(st, 7),
            (long long)sqlite3_column_int64(st, 8), (long long)sqlite3_column_int64(st, 9));
        first = 0;
        size_t ilen = strlen(item);
        if (pos + ilen + 64 >= bufsz) break;
        memcpy(buf + pos, item, ilen);
        pos += ilen;
    }
    sqlite3_finalize(st);
    snprintf(buf + pos, bufsz - pos, "],\"total\":%d,\"limit\":%d,\"offset\":%d}", total, limit, offset);
    return 0;
}

int db_get_session_by_id(long long id, char *buf, size_t bufsz) {
    if (!buf || bufsz == 0) return -1;
    if (!g_db) return 1; /* not found */
    const char *sql = "SELECT id,protocol,client_ip,target_host,target_port,status,bytes_up,bytes_down,started_at,ended_at FROM sessions WHERE id = ?;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, id);
    int rc = 1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        char cipe[130], thoste[520];
        db_json_escape((const char*)sqlite3_column_text(st, 2), cipe, sizeof cipe);
        db_json_escape((const char*)sqlite3_column_text(st, 3), thoste, sizeof thoste);
        snprintf(buf, bufsz,
            "{\"id\":%lld,\"protocol\":\"%s\",\"client_ip\":\"%s\",\"target_host\":\"%s\",\"target_port\":%d,\"status\":%d,\"bytes_up\":%lld,\"bytes_down\":%lld,\"started_at\":%lld,\"ended_at\":%lld}",
            (long long)sqlite3_column_int64(st, 0),
            (const char*)sqlite3_column_text(st, 1), cipe, thoste,
            sqlite3_column_int(st, 4), sqlite3_column_int(st, 5),
            (long long)sqlite3_column_int64(st, 6), (long long)sqlite3_column_int64(st, 7),
            (long long)sqlite3_column_int64(st, 8), (long long)sqlite3_column_int64(st, 9));
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

int db_stats_summary(long long from_ms, long long to_ms, char *buf, size_t bufsz) {
    if (!buf || bufsz == 0) return -1;
    if (!g_db) { snprintf(buf, bufsz, "{\"sessions\":0,\"bytes_up\":0,\"bytes_down\":0,\"errors\":0}"); return 0; }
    /* started_at stored in seconds (time_t); API from/to are unix ms */
    long long from_s = from_ms > 0 ? from_ms / 1000 : -1;
    long long to_s = to_ms > 0 ? to_ms / 1000 : -1;
    const char *sql = "SELECT COUNT(*),COALESCE(SUM(bytes_up),0),COALESCE(SUM(bytes_down),0),COALESCE(SUM(status!=0),0) FROM sessions WHERE (?1<0 OR started_at>=?1) AND (?2<0 OR started_at<=?2);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, from_s);
    sqlite3_bind_int64(st, 2, to_s);
    long long n = 0, up = 0, down = 0, err = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        n = sqlite3_column_int64(st, 0); up = sqlite3_column_int64(st, 1);
        down = sqlite3_column_int64(st, 2); err = sqlite3_column_int64(st, 3);
    }
    sqlite3_finalize(st);
    snprintf(buf, bufsz, "{\"sessions\":%lld,\"bytes_up\":%lld,\"bytes_down\":%lld,\"errors\":%lld}", n, up, down, err);
    return 0;
}

int db_stats_daily(int days, char *buf, size_t bufsz) {
    if (!buf || bufsz == 0) return -1;
    if (days <= 0) days = 30;
    if (days > 365) days = 365;
    if (!g_db) { snprintf(buf, bufsz, "[]"); return 0; }
    const char *sql = "SELECT date(started_at,'unixepoch') d,COUNT(*),COALESCE(SUM(bytes_up),0),COALESCE(SUM(bytes_down),0),COALESCE(SUM(status!=0),0) FROM sessions WHERE started_at >= strftime('%s','now',?||' days') GROUP BY d ORDER BY d;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    char off[16]; snprintf(off, sizeof off, "-%d", days);
    sqlite3_bind_text(st, 1, off, -1, SQLITE_TRANSIENT);
    size_t pos = 0;
    pos += snprintf(buf + pos, bufsz - pos, "[");
    int first = 1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        char item[256];
        snprintf(item, sizeof item, "%s{\"day\":\"%s\",\"sessions\":%lld,\"bytes_up\":%lld,\"bytes_down\":%lld,\"errors\":%lld}",
            first ? "" : ",", (const char*)sqlite3_column_text(st, 0),
            (long long)sqlite3_column_int64(st, 1), (long long)sqlite3_column_int64(st, 2),
            (long long)sqlite3_column_int64(st, 3), (long long)sqlite3_column_int64(st, 4));
        first = 0;
        if (pos + strlen(item) + 2 >= bufsz) break;
        memcpy(buf + pos, item, strlen(item));
        pos += strlen(item);
    }
    sqlite3_finalize(st);
    snprintf(buf + pos, bufsz - pos, "]");
    return 0;
}

int db_stats_top(const char *by, int limit, long long from_ms, long long to_ms, char *buf, size_t bufsz) {
    if (!buf || bufsz == 0) return -1;
    if (limit <= 0) limit = 20;
    if (limit > 100) limit = 100;
    int use_client = (by && strcmp(by, "client") == 0);
    if (!by || (!use_client && strcmp(by, "target") != 0)) return -2; /* invalid */
    if (!g_db) { snprintf(buf, bufsz, "[]"); return 0; }
    long long from_s = from_ms > 0 ? from_ms / 1000 : -1;
    long long to_s = to_ms > 0 ? to_ms / 1000 : -1;
    char sql[512];
    snprintf(sql, sizeof sql, "SELECT %s,COUNT(*),COALESCE(SUM(bytes_up),0)+COALESCE(SUM(bytes_down),0) t FROM sessions WHERE (?1<0 OR started_at>=?1) AND (?2<0 OR started_at<=?2) GROUP BY %s ORDER BY t DESC LIMIT ?3;",
        use_client ? "client_ip" : "target_host", use_client ? "client_ip" : "target_host");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, from_s);
    sqlite3_bind_int64(st, 2, to_s);
    sqlite3_bind_int(st, 3, limit);
    size_t pos = 0;
    pos += snprintf(buf + pos, bufsz - pos, "[");
    int first = 1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        char keye[520];
        db_json_escape((const char*)sqlite3_column_text(st, 0), keye, sizeof keye);
        char item[640];
        snprintf(item, sizeof item, "%s{\"key\":\"%s\",\"sessions\":%lld,\"bytes\":%lld}",
            first ? "" : ",", keye,
            (long long)sqlite3_column_int64(st, 1), (long long)sqlite3_column_int64(st, 2));
        first = 0;
        if (pos + strlen(item) + 2 >= bufsz) break;
        memcpy(buf + pos, item, strlen(item));
        pos += strlen(item);
    }
    sqlite3_finalize(st);
    snprintf(buf + pos, bufsz - pos, "]");
    return 0;
}

int db_settings_get(char *buf, size_t bufsz) {
    if (!buf || bufsz == 0) return -1;
    if (!g_db) { snprintf(buf, bufsz, "{}"); return 0; }
    const char *sql = "SELECT key,value FROM settings;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    size_t pos = 0;
    pos += snprintf(buf + pos, bufsz - pos, "{");
    int first = 1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        char ke[260], ve[1050];
        db_json_escape((const char*)sqlite3_column_text(st, 0), ke, sizeof ke);
        db_json_escape((const char*)sqlite3_column_text(st, 1), ve, sizeof ve);
        char item[1400];
        snprintf(item, sizeof item, "%s\"%s\":\"%s\"", first ? "" : ",", ke, ve);
        first = 0;
        if (pos + strlen(item) + 2 >= bufsz) break;
        memcpy(buf + pos, item, strlen(item));
        pos += strlen(item);
    }
    sqlite3_finalize(st);
    snprintf(buf + pos, bufsz - pos, "}");
    return 0;
}

int db_settings_set(const char *key, const char *value) {
    if (!key || !key[0] || !value) return -1;
    if (!g_db) return -1;
    const char *sql = "INSERT OR REPLACE INTO settings(key,value) VALUES(?1,?2);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, value, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_rules_load(void *router) {
    router_t *rt = (router_t *)router;
    if (!rt) return -1;
    const char *sql = "SELECT id,name,priority,enabled,domain_pattern,geo_ip,geo_site,ip_cidr,port,protocol,upstream_id FROM rules ORDER BY id;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    /* 逐行拼 rule_t：字段拷贝逻辑在 router.c 的导入 helper 里，避免 db.c 依赖 router 布局 */
    char (*rows)[11][96] = NULL;
    size_t n = 0, cap = 0;
    int rc = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 16;
            char (*nr)[11][96] = realloc(rows, ncap * sizeof *nr);
            if (!nr) { sqlite3_finalize(st); free(rows); return -1; }
            rows = nr; cap = ncap;
        }
        for (int c = 0; c < 11; c++) {
            const unsigned char *t = sqlite3_column_text(st, c);
            snprintf(rows[n][c], sizeof rows[n][c], "%s", t ? (const char *)t : "");
        }
        n++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) { free(rows); return -1; }
    int maxid = 0;
    for (size_t i = 0; i < n; i++) {
        int aid = 0;
        if (router_add_rule_persist(rt, rows[i], &aid) == 0 && aid > maxid) maxid = aid;
    }
    free(rows);
    if (maxid >= rt->next_rule_id) rt->next_rule_id = maxid + 1;
    return 0;
}

static pthread_mutex_t g_exec_lock = PTHREAD_MUTEX_INITIALIZER;

int db_exec_raw(const char *sql) {
    if (!g_db || !sql) return -1;
    pthread_mutex_lock(&g_exec_lock);
    char *err = NULL;
    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    pthread_mutex_unlock(&g_exec_lock);
    return (rc == SQLITE_OK) ? 0 : -1;
}

int db_get_recent_sessions(int limit, char *buf, size_t bufsz) {
    if (!buf || bufsz == 0) return -1;
    if (limit <= 0) limit = 100;
    if (limit > 1000) limit = 1000;
    buf[0] = '['; buf[1] = '\0';
    size_t pos = 1;
    if (!g_db) { snprintf(buf, bufsz, "[]"); return 0; }
    const char *sql = "SELECT id,protocol,client_ip,target_host,target_port,status,bytes_up,bytes_down,started_at,ended_at FROM sessions ORDER BY started_at DESC LIMIT ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, limit);
    int first = 1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        char item[512];
        snprintf(item, sizeof item,
            "%s{\"id\":%lld,\"protocol\":\"%s\",\"client_ip\":\"%s\",\"target_host\":\"%s\",\"target_port\":%d,\"status\":%d,\"bytes_up\":%lld,\"bytes_down\":%lld,\"started_at\":%lld,\"ended_at\":%lld}",
            first ? "" : ",",
            (long long)sqlite3_column_int64(stmt, 0),
            (const char*)sqlite3_column_text(stmt, 1),
            (const char*)sqlite3_column_text(stmt, 2),
            (const char*)sqlite3_column_text(stmt, 3),
            sqlite3_column_int(stmt, 4),
            sqlite3_column_int(stmt, 5),
            (long long)sqlite3_column_int64(stmt, 6),
            (long long)sqlite3_column_int64(stmt, 7),
            (long long)sqlite3_column_int64(stmt, 8),
            (long long)sqlite3_column_int64(stmt, 9));
        first = 0;
        size_t ilen = strlen(item);
        if (pos + ilen + 2 >= bufsz) break;
        memcpy(buf + pos, item, ilen);
        pos += ilen;
    }
    sqlite3_finalize(stmt);
    if (pos + 2 < bufsz) {
        buf[pos] = ']';
        buf[pos+1] = '\0';
    } else {
        buf[bufsz-2] = ']';
        buf[bufsz-1] = '\0';
    }
    return 0;
}
