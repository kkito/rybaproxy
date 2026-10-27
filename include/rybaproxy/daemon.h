/* 守护化与停止。
 * 只放进程生命周期胶水；判定逻辑在 pidfile.h 的纯函数里。 */
#ifndef RYBAPROXY_DAEMON_H
#define RYBAPROXY_DAEMON_H

#include <sys/types.h>

/* 守护化：双 fork + setsid + stdio 重定向 /dev/null + chdir("/")。
 * 返回值：
 *   -1  失败（调用方按前台继续或报错退出）
 *    0  当前进程就是守护进程，调用方继续正常启动
 *   >0  当前是原进程，返回值为守护进程 pid；调用方应打印摘要后退出 */
pid_t daemon_detach(void);

/* 停止：读 pidfile → SIGTERM → 轮询等待 → 超时 SIGKILL → 删 pidfile。
 * 没 pidfile / 进程已死 / 内容非法都算"已经停了"，返回 0（幂等）。
 * 杀不动才返回 -1。 */
int daemon_stop(const char *pidfile, int timeout_sec);

#endif
