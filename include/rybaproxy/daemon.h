/* 守护化与停止。
 * 只放进程生命周期胶水；判定逻辑在 pidfile.h 的纯函数里。 */
#ifndef RYBAPROXY_DAEMON_H
#define RYBAPROXY_DAEMON_H

#include <sys/types.h>

/* 守护化：双 fork + setsid + stdio 重定向 /dev/null + chdir("/")。
 * ready_fd：就绪握手的管道端。
 *   父进程侧拿到读端，守护进程侧拿到写端。
 * 返回值：
 *   -1  失败（调用方按前台继续或报错退出）
 *    0  当前进程就是守护进程，调用方继续正常启动
 *   >0  当前是原进程，返回值为守护进程 pid；调用方应等待就绪后打印摘要 */
pid_t daemon_detach(int *ready_fd);

/* 守护进程侧：err==NULL 表示启动成功；否则把失败原因回传给父进程 */
void daemon_report(int fd, const char *err);

/* 父进程侧：阻塞等待守护进程就绪或失败。
 * 返回 1=就绪；0=失败/超时（原因写入 err）。 */
int daemon_wait_ready(int fd, char *err, size_t errsz, int timeout_sec);

/* 停止：读 pidfile → SIGTERM → 轮询等待 → 超时 SIGKILL → 删 pidfile。
 * 没 pidfile / 进程已死 / 内容非法都算"已经停了"，返回 0（幂等）。
 * 杀不动才返回 -1。 */
int daemon_stop(const char *pidfile, int timeout_sec);

#endif
