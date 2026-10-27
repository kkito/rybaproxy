#ifndef RYBAPROXY_LOG_H
#define RYBAPROXY_LOG_H

#include <stdio.h>
#include <stdlib.h>

typedef enum { LOG_TRACE=0, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL } log_level_t;

/* 级别名解析纯函数：大小写不敏感，未知/空回 LOG_INFO */
int log_level_parse(const char *s);

void log_init(log_level_t level, const char *file);
void log_set_level(log_level_t level);
void log_msg(log_level_t level, const char *file, int line, const char *fmt, ...);

#define LOG_TRACE(...) log_msg(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) log_msg(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)  log_msg(LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  log_msg(LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) log_msg(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_FATAL(...) log_msg(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

#endif
