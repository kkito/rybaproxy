/* pidfile 单测：分类矩阵走纯函数，文件读写/探活用临时目录 + 自身 pid，
 * 不碰家目录、不碰网络。 */
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rybaproxy/pidfile.h"

static char g_dir[128];

static int setup(void **state) {
    (void)state;
    snprintf(g_dir, sizeof g_dir, "/tmp/ryba_pid_%d", (int)getpid());
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

/* 纯函数矩阵：四种输入组合各就各位 */
static void test_classify_matrix(void **state) {
    (void)state;
    assert_int_equal(pidfile_classify(0, 0, 0), PIDFILE_MISSING);
    assert_int_equal(pidfile_classify(0, 1, 1), PIDFILE_MISSING);
    assert_int_equal(pidfile_classify(1, 0, 0), PIDFILE_MALFORMED);
    assert_int_equal(pidfile_classify(1, 0, 1), PIDFILE_MALFORMED);
    assert_int_equal(pidfile_classify(1, 1, 0), PIDFILE_STALE);
    assert_int_equal(pidfile_classify(1, 1, 1), PIDFILE_RUNNING);
}

/* 写自己再读回来：probe 必须判 RUNNING */
static void test_write_read_roundtrip(void **state) {
    (void)state;
    char path[256];
    snprintf(path, sizeof path, "%s/rybaproxy.pid", g_dir);
    assert_int_equal(pidfile_write(path, (long)getpid()), 0);
    long pid = 0;
    assert_int_equal(pidfile_read(path, &pid), 0);
    assert_int_equal(pid, (long)getpid());
    assert_int_equal(pidfile_probe(path), PIDFILE_RUNNING);
    /* 自己当然活着 */
    assert_int_equal(pid_alive((long)getpid()), 1);
    assert_int_equal(pidfile_remove(path), 0);
    assert_int_equal(pidfile_probe(path), PIDFILE_MISSING);
}

/* 进程已死：必须判 STALE，这是"重启后残留"的正常路径 */
static void test_stale_when_process_dead(void **state) {
    (void)state;
    char path[256];
    snprintf(path, sizeof path, "%s/stale.pid", g_dir);
    /* 取一个几乎不可能存在的 pid：内核默认 pid_max 上限之内随便挑个大的 */
    long dead = 999999999L;
    assert_int_equal(pid_alive(dead), 0);
    assert_int_equal(pidfile_write(path, dead), 0);
    assert_int_equal(pidfile_probe(path), PIDFILE_STALE);
    assert_int_equal(pid_alive(dead), 0);
}

/* 内容不是数字：MALFORMED，不能当成 RUNNING 把用户挡在门外 */
static void test_malformed(void **state) {
    (void)state;
    char path[256];
    snprintf(path, sizeof path, "%s/bad.pid", g_dir);
    FILE *f = fopen(path, "w");
    fprintf(f, "not-a-pid\n");
    fclose(f);
    long pid = 0;
    assert_int_equal(pidfile_read(path, &pid), -2);
    assert_int_equal(pidfile_probe(path), PIDFILE_MALFORMED);
}

/* 空文件同样算非法 */
static void test_empty_file_is_malformed(void **state) {
    (void)state;
    char path[256];
    snprintf(path, sizeof path, "%s/empty.pid", g_dir);
    FILE *f = fopen(path, "w");
    fclose(f);
    assert_int_equal(pidfile_probe(path), PIDFILE_MALFORMED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_classify_matrix),
        cmocka_unit_test_setup_teardown(test_write_read_roundtrip, setup, teardown),
        cmocka_unit_test_setup_teardown(test_stale_when_process_dead, setup, teardown),
        cmocka_unit_test_setup_teardown(test_malformed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_empty_file_is_malformed, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
