/* 启动时打印的基本信息。格式化是纯函数（入参 → 字符串），
 * 不碰 stdout/日志/进程状态，方便单测锁定输出格式。 */
#ifndef RYBAPROXY_STARTUP_INFO_H
#define RYBAPROXY_STARTUP_INFO_H

#include <stddef.h>

#include "rybaproxy/common.h"

typedef struct {
    char version[64];
    char commit[32];
    char build_time[40];
    char config_path[256];
    char data_dir[256];
    char db_path[512];
    char log_file[512];
    char log_level[16];
    char pid_file[512];
    long pid;
    int http_port;
    int socks5_port;
    int web_port;
    char upstreams[512];   /* upstream_summary() 的输出 */
    int upstream_count;
    int rule_count;
    int geo_ip_count;    /* <0 = geo 库未加载 */
    int geo_site_count;
    int geo_cache_size;
    int detached;
} startup_info_t;

/* 纯函数：把启动信息格式化成多行文本（写入 out，返回 strlen） */
size_t startup_info_text(const startup_info_t *info, char *out, size_t outsz);

/* 纯函数：上游列表摘要，如 "proxy http://172.27.128.253:7890, direct"；
 * 空列表返回 "(none)"。禁用项标 (off)。 */
size_t upstream_summary(const upstream_profile_t *ups, int n, char *out, size_t outsz);

#endif
