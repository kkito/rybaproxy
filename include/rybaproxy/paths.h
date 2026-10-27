#ifndef RYBAPROXY_PATHS_H
#define RYBAPROXY_PATHS_H

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>

/* 默认数据目录：$HOME/.local/rybaproxy；HOME 为空则回退 "."。
 * 纯 inline helper，供 config/db/geo 三处复用，避免三份 HOME 拼接逻辑。 */
static inline int ryba_data_dir(const char *home, char *out, size_t outsz) {
    if (!out || outsz == 0) return -1;
    if (home && *home) snprintf(out, outsz, "%s/.local/rybaproxy", home);
    else snprintf(out, outsz, ".");
    return 0;
}

/* 默认 db 路径：<data_dir>/stats.db（config 默认值 + db 空路径回退共用） */
static inline int ryba_default_db_path(const char *home, char *out, size_t outsz) {
    char dir[512];
    if (!out || outsz == 0) return -1;
    if (ryba_data_dir(home, dir, sizeof dir) != 0) return -1;
    snprintf(out, outsz, "%s/rybaproxy.db", dir);
    return 0;
}

/* 默认日志路径：<data_dir>/rybaproxy.log */
static inline int ryba_default_log_path(const char *home, char *out, size_t outsz) {
    char dir[512];
    if (!out || outsz == 0) return -1;
    if (ryba_data_dir(home, dir, sizeof dir) != 0) return -1;
    snprintf(out, outsz, "%s/rybaproxy.log", dir);
    return 0;
}

/* 默认 pidfile 路径：<data_dir>/rybaproxy.pid */
static inline int ryba_default_pid_path(const char *home, char *out, size_t outsz) {
    char dir[512];
    if (!out || outsz == 0) return -1;
    if (ryba_data_dir(home, dir, sizeof dir) != 0) return -1;
    snprintf(out, outsz, "%s/rybaproxy.pid", dir);
    return 0;
}

/* 递归建目录（含父目录），已存在也算成功 */
static inline int ryba_ensure_dir(const char *dir) {
    if (!dir || !*dir) return -1;
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s", dir);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    return (mkdir(tmp, 0755) == 0 || errno == EEXIST) ? 0 : -1;
}

#endif
