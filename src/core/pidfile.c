#include "rybaproxy/pidfile.h"

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 纯函数：三种事实 → 状态。顺序即优先级：没文件 > 内容非法 > 进程已死 > 在跑 */
pidfile_state_t pidfile_classify(int has_file, int pid_valid, int alive) {
    if (!has_file) return PIDFILE_MISSING;
    if (!pid_valid) return PIDFILE_MALFORMED;
    if (!alive) return PIDFILE_STALE;
    return PIDFILE_RUNNING;
}

int pidfile_read(const char *path, long *pid) {
    if (!path || !pid) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[64] = {0};
    if (!fgets(buf, sizeof buf, f)) { fclose(f); return -2; }
    fclose(f);
    char *end = NULL;
    errno = 0;
    long v = strtol(buf, &end, 10);
    if (errno != 0 || end == buf || v <= 0) return -2;
    /* 允许尾随空白/换行，其余字符算非法 */
    while (end && *end && isspace((unsigned char)*end)) end++;
    if (end && *end) return -2;
    *pid = v;
    return 0;
}

int pidfile_write(const char *path, long pid) {
    if (!path || pid <= 0) return -1;
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    if (fprintf(f, "%ld\n", pid) < 0) { fclose(f); return -1; }
    if (fclose(f) != 0) return -1;
    return 0;
}

int pidfile_remove(const char *path) {
    if (!path) return -1;
    return (remove(path) == 0 || errno == ENOENT) ? 0 : -1;
}

int pid_alive(long pid) {
    if (pid <= 0) return -1;
    if (kill((pid_t)pid, 0) == 0) return 1;
    /* EPERM：进程存在但不属于我们，仍然算活着 */
    return (errno == ESRCH) ? 0 : 1;
}

pidfile_state_t pidfile_probe(const char *path) {
    long pid = 0;
    int rc = pidfile_read(path, &pid);
    if (rc == -1) return PIDFILE_MISSING;
    if (rc != 0) return PIDFILE_MALFORMED;
    return pidfile_classify(1, 1, pid_alive(pid) == 1);
}
