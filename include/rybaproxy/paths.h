#ifndef RYBAPROXY_PATHS_H
#define RYBAPROXY_PATHS_H

#include <stddef.h>
#include <stdio.h>

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
    snprintf(out, outsz, "%s/stats.db", dir);
    return 0;
}

#endif
