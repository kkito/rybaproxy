#include "rybaproxy/daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rybaproxy/pidfile.h"

pid_t daemon_detach(int *ready_fd) {
    /* 管道：守护进程把自己的真实 pid 和启动结果回传给原进程。
     * 双 fork 下第一层子进程会立刻退出，父进程拿到的不是守护进程 pid；
     * 而守护进程启动失败时父进程也必须知道，不能谎报成功。 */
    int fds[2];
    if (pipe(fds) != 0) return -1;

    /* 第一次 fork：让 shell 认为命令已结束 */
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }
    if (pid > 0) {
        close(fds[1]);
        if (ready_fd) *ready_fd = fds[0];
        pid_t dpid = 0;
        if (read(fds[0], &dpid, sizeof dpid) != (ssize_t)sizeof dpid) {
            close(fds[0]);
            return -1;
        }
        return dpid;
    }

    /* 子进程：脱离会话，成为进程组首领 */
    close(fds[0]);
    if (ready_fd) *ready_fd = fds[1];
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
    }

    /* stdio 丢去 /dev/null：日志已落盘，不能再往已关闭的终端写 */
    int nfd = open("/dev/null", O_RDWR);
    if (nfd >= 0) {
        dup2(nfd, STDIN_FILENO);
        dup2(nfd, STDOUT_FILENO);
        dup2(nfd, STDERR_FILENO);
        if (nfd > STDERR_FILENO) close(nfd);
    }
    (void)chdir("/");
    umask(022);
    return 0;
}

/* 协议：先写 4 字节 pid（daemon_detach 已发），随后一行 "OK\\n" 或 "ERR <原因>\\n" */
void daemon_report(int fd, const char *err) {
    if (fd < 0) return;
    if (err && *err) {
        if (dprintf(fd, "ERR %s\n", err) < 0) { /* 尽力而为 */ }
    } else {
        if (dprintf(fd, "OK\n") < 0) { /* 尽力而为 */ }
    }
    close(fd);
}

int daemon_wait_ready(int fd, char *err, size_t errsz, int timeout_sec) {
    if (fd < 0) return 0;
    char buf[512] = {0};
    size_t used = 0;
    /* 轮询读：父进程不该无限期干等，超时即判失败 */
    int deadline_ms = (timeout_sec > 0 ? timeout_sec : 1) * 1000;
    int waited = 0;
    while (waited < deadline_ms) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 200);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        if (pr > 0) {
            ssize_t n = read(fd, buf + used, sizeof buf - 1 - used);
            if (n > 0) {
                used += (size_t)n;
                buf[used] = '\0';
                if (strchr(buf, '\n') || used >= sizeof buf - 1) break;
                continue;
            }
            if (n == 0) break;   /* 对端关闭：写不动了，按失败处理 */
            if (errno == EINTR) continue;
            break;
        }
        waited += 200;
    }
    close(fd);
    if (used == 0) {
        if (err && errsz) snprintf(err, errsz, "daemon exited before reporting ready");
        return 0;
    }
    if (strncmp(buf, "OK", 2) == 0) return 1;
    char *msg = buf;
    if (strncmp(buf, "ERR ", 4) == 0) msg = buf + 4;
    char *nl = strchr(msg, '\n');
    if (nl) *nl = '\0';
    if (err && errsz) snprintf(err, errsz, "%s", msg);
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
