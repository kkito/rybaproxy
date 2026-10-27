/* daemon 单测：全部用真子进程验证（fork + sleep + 信号），
 * 不 mock 信号、不碰家目录、不碰网络。
 * 注意：子进程里不能调 cmocka 断言，只用管道/退出码回传结果。 */
#include <cmocka.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rybaproxy/daemon.h"
#include "rybaproxy/pidfile.h"

static char g_dir[128];

static int setup(void **state) {
    (void)state;
    snprintf(g_dir, sizeof g_dir, "/tmp/ryba_dmn_%d", (int)getpid());
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -rf %s && mkdir -p %s", g_dir, g_dir);
    if (system(cmd) != 0) return -1;
    return 0;
}

static int teardown(void **state) {
    (void)state;
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -rf %s", g_dir);
    (void)system(cmd);
    return 0;
}

static void wait_gone(pid_t pid) {
    for (int i = 0; i < 100 && pid_alive(pid); i++) usleep(100000);
}

/* 造一个"孤儿"进程：双 fork 后被 init/launchd 收养，与真实守护进程一样
 * 死后不会变僵尸——否则 kill(pid,0) 对僵尸仍成功，pid_alive 会误判存活。 */
static pid_t spawn_orphan(int ignore_term) {
    int fds[2];
    assert_int_equal(pipe(fds), 0);
    pid_t mid = fork();
    assert_true(mid >= 0);
    if (mid == 0) {
        close(fds[0]);
        pid_t g = fork();
        if (g == 0) {
            signal(SIGTERM, ignore_term ? SIG_IGN : SIG_DFL);
            signal(SIGHUP, SIG_DFL);
            pid_t self = getpid();
            if (write(fds[1], &self, sizeof self) != (ssize_t)sizeof self) _exit(9);
            close(fds[1]);
            for (;;) pause();
            _exit(0);
        }
        if (g < 0) _exit(8);
        close(fds[1]);
        _exit(0);              /* 中间层立刻退出，孙进程被收养 */
    }
    close(fds[1]);
    pid_t pid = 0;
    ssize_t n = read(fds[0], &pid, sizeof pid);
    close(fds[0]);
    int st = 0;
    waitpid(mid, &st, 0);
    assert_int_equal(n, (ssize_t)sizeof pid);
    return pid;
}

/* 守护化后必须得到一个脱离终端的活进程，且父进程拿到它的 pid */
static void test_detach_spawns_daemon(void **state) {
    (void)state;
    int fds[2];
    assert_int_equal(pipe(fds), 0);
    pid_t child = fork();
    assert_true(child >= 0);
    if (child == 0) {
        close(fds[0]);
        pid_t d = daemon_detach();
        if (d <= 0) _exit(d == 0 ? 0 : 3);   /* 0=我是守护进程 */
        /* 父进程路径：把守护 pid 写回管道后退出 */
        if (write(fds[1], &d, sizeof d) != (ssize_t)sizeof d) _exit(4);
        close(fds[1]);
        _exit(0);
    }
    close(fds[1]);
    pid_t dpid = 0;
    ssize_t n = read(fds[0], &dpid, sizeof dpid);
    close(fds[0]);
    assert_int_equal(n, (ssize_t)sizeof dpid);
    assert_true(dpid > 0);
    int st = 0;
    waitpid(child, &st, 0);                    /* 原子进程必须立刻退出 */
    assert_int_equal(WIFEXITED(st), 1);
    assert_int_equal(WEXITSTATUS(st), 0);
    /* 守护进程活着，且不是原子进程本身 */
    assert_int_equal(pid_alive(dpid), 1);
    assert_true(dpid != child);
    kill(dpid, SIGTERM);
    wait_gone(dpid);
    assert_int_equal(pid_alive(dpid), 0);
}

/* 普通子进程 + 自己的 pidfile：stop 必须 SIGTERM 掉它并清掉 pidfile */
static void test_stop_terminates_child(void **state) {
    (void)state;
    char path[256];
    snprintf(path, sizeof path, "%s/rybaproxy.pid", g_dir);
    pid_t child = spawn_orphan(0);
    assert_true(child > 0);
    assert_int_equal(pidfile_write(path, (long)child), 0);
    assert_int_equal(pidfile_probe(path), PIDFILE_RUNNING);
    assert_int_equal(daemon_stop(path, 5), 0);
    assert_int_equal(pid_alive(child), 0);
    /* pidfile 必须被清掉，否则下次启动误判"已在运行" */
    assert_int_equal(pidfile_probe(path), PIDFILE_MISSING);
}

/* 没 pidfile：本来就没跑，返回成功（幂等） */
static void test_stop_when_not_running(void **state) {
    (void)state;
    char path[256];
    snprintf(path, sizeof path, "%s/none.pid", g_dir);
    assert_int_equal(daemon_stop(path, 1), 0);
    assert_int_equal(pidfile_probe(path), PIDFILE_MISSING);
}

/* pidfile 在但进程已死：清残留后返回成功 */
static void test_stop_clears_stale(void **state) {
    (void)state;
    char path[256];
    snprintf(path, sizeof path, "%s/stale.pid", g_dir);
    assert_int_equal(pidfile_write(path, 999999999L), 0);
    assert_int_equal(daemon_stop(path, 1), 0);
    assert_int_equal(pidfile_probe(path), PIDFILE_MISSING);
}

/* pidfile 内容非法：不能把用户挡在门外，清掉返回成功 */
static void test_stop_clears_malformed(void **state) {
    (void)state;
    char path[256];
    snprintf(path, sizeof path, "%s/bad.pid", g_dir);
    FILE *f = fopen(path, "w");
    fprintf(f, "garbage\n");
    fclose(f);
    assert_int_equal(daemon_stop(path, 1), 0);
    assert_int_equal(pidfile_probe(path), PIDFILE_MISSING);
}

/* 子进程赖着不死（忽略 SIGTERM）：超时后必须升级到 SIGKILL */
static void test_stop_escalates_to_sigkill(void **state) {
    (void)state;
    char path[256];
    snprintf(path, sizeof path, "%s/stubborn.pid", g_dir);
    pid_t child = spawn_orphan(1);   /* 忽略 SIGTERM，逼出 SIGKILL 路径 */
    assert_true(child > 0);
    assert_int_equal(pidfile_write(path, (long)child), 0);
    assert_int_equal(daemon_stop(path, 1), 0);   /* 1 秒后 SIGKILL */
    assert_int_equal(pid_alive(child), 0);
    assert_int_equal(pidfile_probe(path), PIDFILE_MISSING);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_detach_spawns_daemon, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stop_terminates_child, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stop_when_not_running, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stop_clears_stale, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stop_clears_malformed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stop_escalates_to_sigkill, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
