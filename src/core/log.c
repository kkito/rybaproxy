#include "rybaproxy/log.h"

#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static log_level_t g_level = LOG_INFO;
static FILE *g_file = NULL;
static int g_close = 0;

static const char *level_name(log_level_t l) {
    switch (l) {
        case LOG_TRACE: return "TRACE";
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO";
        case LOG_WARN:  return "WARN";
        case LOG_ERROR: return "ERROR";
        case LOG_FATAL: return "FATAL";
    }
    return "?";
}

void log_init(log_level_t level, const char *file) {
    g_level = level;
    if (file && file[0]) {
        g_file = fopen(file, "a");
        if (!g_file) { g_file = stderr; }
        else g_close = 1;
    } else {
        g_file = stderr;
    }
}

void log_set_level(log_level_t level) { g_level = level; }

int log_level_parse(const char *s) {
    if (!s || !*s) return LOG_INFO;
    if (strcasecmp(s, "trace") == 0) return LOG_TRACE;
    if (strcasecmp(s, "debug") == 0) return LOG_DEBUG;
    if (strcasecmp(s, "info") == 0) return LOG_INFO;
    if (strcasecmp(s, "warn") == 0 || strcasecmp(s, "warning") == 0) return LOG_WARN;
    if (strcasecmp(s, "error") == 0) return LOG_ERROR;
    if (strcasecmp(s, "fatal") == 0) return LOG_FATAL;
    return LOG_INFO;
}

void log_msg(log_level_t level, const char *file, int line, const char *fmt, ...) {
    if (level < g_level) return;
    if (!g_file) g_file = stderr;
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(g_file, "%s %-5s %s:%d: ", ts, level_name(level), file, line);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_file, fmt, ap);
    va_end(ap);
    fputc('\n', g_file);
    fflush(g_file);
    if (level == LOG_FATAL) {
        if (g_close && g_file) fclose(g_file);
        abort();
    }
}
