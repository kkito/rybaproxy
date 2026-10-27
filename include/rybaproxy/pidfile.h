/* pidfile：启动互斥 + stop 定位进程。
 * 判定逻辑（该放行还是该报"已在运行"）是纯函数，IO 只留读写/探活薄胶水。 */
#ifndef RYBAPROXY_PIDFILE_H
#define RYBAPROXY_PIDFILE_H

#include <sys/types.h>

typedef enum {
    PIDFILE_MISSING = 0,  /* 没有 pidfile：可以启动 */
    PIDFILE_RUNNING,      /* pidfile 里的进程还活着：禁止重复启动 */
    PIDFILE_STALE,        /* pidfile 在但进程已死：清掉重用 */
    PIDFILE_MALFORMED     /* 内容不是合法 pid：按残留处理 */
} pidfile_state_t;

/* 纯函数：读文件结果 + 探活结果 → 状态。测试不碰文件系统。 */
pidfile_state_t pidfile_classify(int has_file, int pid_valid, int alive);

/* 薄胶水：读 pidfile。0=读到合法 pid，-1=打不开/不存在，-2=内容非法 */
int pidfile_read(const char *path, long *pid);
/* 薄胶水：写 pidfile（覆盖）。0=成功 */
int pidfile_write(const char *path, long pid);
int pidfile_remove(const char *path);
/* 探活：kill(pid,0)。1=活着，0=已死，-1=参数非法 */
int pid_alive(long pid);
/* 胶水：read + alive + classify 一条龙 */
pidfile_state_t pidfile_probe(const char *path);

#endif
