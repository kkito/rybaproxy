#include "rybaproxy/daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rybaproxy/pidfile.h"

pid_t daemon_detach(void) {
    /* 管道：守护进程把自己的真实 pid 回传给原进程。
     * 双 fork 下第一层子进程会立刻退出，父进程拿到的不是守护进程 pid。 */
    int fds[2];
    if (pipe(fds) != 0) return -1;

    /* 第一次 fork：让 shell 认为命令已结束 */
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }
    if (pid > 0) {
        close(fds[1]);
        pid_t dpid = 0;
        if (read(fds[0], &dpid, sizeof dpid) != (ssize_t)sizeof dpid) dpid = -1;
        close(fds[0]);
        return dpid;
    }

    /* 子进程：脱离会话，成为进程组首领 */
    close(fds[0]);
    if (setsid() < 0) _exit(1);
    signal(SIGHUP, SIG_IGN);

    /* 第二次 fork：确保再也无法抢占控制终端 */
    pid = fork();
    if (pid < 0) _exit(1);
    if (pid > 0) _exit(0);

    /* 守护进程：第一件事就是把真实 pid 告诉父进程 */
    {
        pid_t self = getpid();
        if (write(fds[1], &self, sizeof self) != (ssize_t)sizeof self) _exit(1);
        close(fds[1]);
    }

    /* stdio 丢去 /dev/null：日志已落盘，不能再往已关闭的终端写 */
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
    (void)chdir("/");
    umask(022);
    return 0;
}

int daemon_stop(const char *pidfile, int timeout_sec) {
    if (!pidfile) return -1;
    long pid = 0;
    int rc = pidfile_read(pidfile, &pid);
    if (rc == -1) return 0;                          /* 没 pidfile：本来就没跑 */
    if (rc != 0) { (void)pidfile_remove(pidfile); return 0; }   /* 内容非法 */
    if (!pid_alive(pid)) { (void)pidfile_remove(pidfile); return 0; }  /* 残留 */

    if (kill((pid_t)pid, SIGTERM) != 0 && errno != ESRCH) return -1;

    int wait_ms = (timeout_sec > 0 ? timeout_sec : 1) * 1000;
    for (int i = 0; i < wait_ms / 100; i++) {
        if (!pid_alive(pid)) { (void)pidfile_remove(pidfile); return 0; }
        usleep(100000);
    }
    /* 超时：升级 SIGKILL，再等 5 秒 */
    (void)kill((pid_t)pid, SIGKILL);
    for (int i = 0; i < 50; i++) {
        if (!pid_alive(pid)) break;
        usleep(100000);
    }
    (void)pidfile_remove(pidfile);
    return pid_alive(pid) ? -1 : 0;
}
