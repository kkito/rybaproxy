#include "rybaproxy/config.h"
#include "rybaproxy/daemon.h"
#include "rybaproxy/db.h"
#include "rybaproxy/geo.h"
#include "rybaproxy/log.h"
#include "rybaproxy/paths.h"
#include "rybaproxy/pidfile.h"
#include "rybaproxy/server.h"
#include "rybaproxy/startup_info.h"
#include "rybaproxy/stats.h"
#include "rybaproxy/web.h"
#include "rybaproxy/version.h"

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static server_ctx_t *g_srv = NULL;

static void on_signal(int sig) {
    (void)sig;
    if (g_srv && g_srv->base) {
        event_base_loopbreak(g_srv->base);
    }
}

static void usage(FILE *out) {
    fprintf(out,
        "Usage: rybaproxy [start|stop] [options]\n"
        "\n"
        "Commands:\n"
        "  start                start the proxy in the foreground (default)\n"
        "  stop                 stop the running instance (via pidfile)\n"
        "\n"
        "Options:\n"
        "  -c, --config FILE    config file path\n"
        "  -d, --detach         run as a background daemon (start only)\n"
        "  -h, --help           show this help\n"
        "  -v, --version        show version\n"
        "\n"
        "With no command, rybaproxy starts in the foreground, same as `start`.\n");
}

/* 日志落盘：默认 <data>/rybaproxy.log；目录自动建，失败回退 stderr */
static int open_log_file(const config_t *cfg) {
    log_level_t lvl = (log_level_t)log_level_parse(cfg->log_level);
    char logdir[1024];
    snprintf(logdir, sizeof logdir, "%s", cfg->log_file);
    char *slash = strrchr(logdir, '/');
    if (slash) { *slash = '\0'; ryba_ensure_dir(logdir); }
    FILE *probe = cfg->log_file[0] ? fopen(cfg->log_file, "a") : NULL;
    if (probe) { fclose(probe); log_init(lvl, cfg->log_file); return 0; }
    log_init(lvl, NULL);
    if (cfg->log_file[0])
        fprintf(stderr, "warn: cannot open log %s, fallback to stderr\n", cfg->log_file);
    return -1;
}

static void print_banner(const startup_info_t *info, int detached) {
    char text[2048];
    startup_info_text(info, text, sizeof text);
    if (detached) {
        /* 守护模式 stdio 已丢去 /dev/null，只能进日志 */
        LOG_INFO("startup:\n%s", text);
    } else {
        fputs(text, stdout);
        fflush(stdout);
    }
}

static int cmd_stop(const char *config_path) {
    config_t cfg;
    config_init_defaults(&cfg);
    if (config_path && config_load(config_path, &cfg) != 0) {
        fprintf(stderr, "error: failed to load config: %s\n", config_path);
        return 1;
    }
    long pid = 0;
    int rc = pidfile_read(cfg.pid_file, &pid);
    if (rc == -1) {
        printf("rybaproxy is not running\n");
        return 0;
    }
    if (rc != 0) {
        printf("removing malformed pidfile %s\n", cfg.pid_file);
        (void)pidfile_remove(cfg.pid_file);
        return 0;
    }
    if (!pid_alive(pid)) {
        printf("removing stale pidfile %s (pid %ld not running)\n", cfg.pid_file, pid);
        (void)pidfile_remove(cfg.pid_file);
        return 0;
    }
    printf("stopping rybaproxy (pid %ld) ...\n", pid);
    if (daemon_stop(cfg.pid_file, 10) != 0) {
        fprintf(stderr, "error: failed to stop pid %ld\n", pid);
        return 1;
    }
    printf("rybaproxy stopped\n");
    return 0;
}

static int cmd_start(const char *config_path, int detach) {
    config_t cfg;
    config_init_defaults(&cfg);
    if (config_path) {
        if (config_load(config_path, &cfg) != 0) {
            fprintf(stderr, "error: failed to load config: %s\n", config_path);
            return 1;
        }
    }
    open_log_file(&cfg);

    /* 启动互斥：pidfile 里的进程还活着就拒绝，避免两个实例抢同一个端口 */
    pidfile_state_t st = pidfile_probe(cfg.pid_file);
    if (st == PIDFILE_RUNNING) {
        long pid = 0;
        (void)pidfile_read(cfg.pid_file, &pid);
        fprintf(stderr, "error: rybaproxy already running (pid %ld, pidfile %s)\n",
                pid, cfg.pid_file);
        return 1;
    }
    if (st == PIDFILE_STALE || st == PIDFILE_MALFORMED) {
        LOG_WARN("removing leftover pidfile %s", cfg.pid_file);
        (void)pidfile_remove(cfg.pid_file);
    }

    /* 守护化：父进程只负责告知"起来了"，其余初始化全部在守护进程里做 */
    if (detach) {
        pid_t dpid = daemon_detach();
        if (dpid < 0) {
            fprintf(stderr, "error: daemon_detach failed\n");
            return 1;
        }
        if (dpid > 0) {
            printf("rybaproxy started in background (pid %d), log: %s\n", (int)dpid, cfg.log_file);
            fflush(stdout);
            return 0;
        }
    }

    if (pidfile_write(cfg.pid_file, (long)getpid()) != 0)
        LOG_WARN("cannot write pidfile %s, `rybaproxy stop` will not find this instance", cfg.pid_file);

    geo_set_cache_size(cfg.geo_cache_size);
    stats_init();

    if (db_init(cfg.db_path) != 0) fprintf(stderr, "db_init failed\n");
    db_set_retention(cfg.retention_days);
    db_start();

    g_srv = calloc(1, sizeof *g_srv);
    if (server_init(g_srv, &cfg) != 0) {
        LOG_ERROR("server_init failed");
        (void)pidfile_remove(cfg.pid_file);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    geo_init();
    {
        char gdir[512];
        if (geo_active_dir(cfg.geo_dir, gdir, sizeof gdir) != 0) snprintf(gdir, sizeof gdir, ".");
        if (geo_load(gdir) == 0)
            LOG_INFO("geo db loaded: ip=%zu site=%zu", geo_ip_count(), geo_site_count());
        else
            LOG_INFO("geo db not loaded (dir %s), geo rules match as unknown", gdir);
    }

    g_srv->web_ctx = web_start(g_srv, cfg.web_port);
    LOG_INFO("rybaproxy listening http=%d socks5=%d web=%d", cfg.http_port, cfg.socks5_port, cfg.web_port);

    {
        startup_info_t info;
        memset(&info, 0, sizeof info);
        snprintf(info.version, sizeof info.version, "%s", RYBA_VERSION_FULL);
        snprintf(info.commit, sizeof info.commit, "%s", RYBA_GIT_COMMIT);
        snprintf(info.build_time, sizeof info.build_time, "%s", RYBA_BUILD_TIME);
        snprintf(info.config_path, sizeof info.config_path, "%s", config_path ? config_path : "");
        snprintf(info.data_dir, sizeof info.data_dir, "%s", cfg.db_path);
        char *slash = strrchr(info.data_dir, '/');
        if (slash) *slash = '\0';
        snprintf(info.db_path, sizeof info.db_path, "%s", cfg.db_path);
        snprintf(info.log_file, sizeof info.log_file, "%s", cfg.log_file);
        snprintf(info.log_level, sizeof info.log_level, "%s", cfg.log_level);
        snprintf(info.pid_file, sizeof info.pid_file, "%s", cfg.pid_file);
        info.pid = (long)getpid();
        info.http_port = cfg.http_port;
        info.socks5_port = cfg.socks5_port;
        info.web_port = cfg.web_port;
        info.upstream_count = g_srv->upstream_count;
        upstream_summary(g_srv->upstreams, g_srv->upstream_count, info.upstreams, sizeof info.upstreams);
        info.rule_count = g_srv->router.count;
        info.geo_ip_count = geo_ip_count() ? (int)geo_ip_count() : -1;
        info.geo_site_count = geo_site_count() ? (int)geo_site_count() : -1;
        info.geo_cache_size = cfg.geo_cache_size;
        info.detached = detach;
        print_banner(&info, detach);
    }

    server_run(g_srv);

    geo_free();
    db_stop();
    server_free(g_srv);
    (void)pidfile_remove(cfg.pid_file);   /* 必须在 config_free 之前，否则读已释放内存 */
    config_free(&cfg);
    free(g_srv);
    g_srv = NULL;
    LOG_INFO("shutdown");
    return 0;
}

int main(int argc, char **argv) {
    const char *cmd = "start";
    int argi = 1;
    /* 子命令必须是第一个参数：`rybaproxy start -c x`，`rybaproxy -c x` 保持旧行为 */
    if (argc > 1 && argv[1][0] != '-') {
        if (strcmp(argv[1], "start") == 0 || strcmp(argv[1], "stop") == 0) {
            cmd = argv[1];
            argi = 2;
        } else {
            fprintf(stderr, "error: unknown command '%s'\n", argv[1]);
            usage(stderr);
            return 1;
        }
    }

    optind = argi;
    const char *config_path = NULL;
    int detach = 0;
    static const struct option opts[] = {
        {"config",  required_argument, 0, 'c'},
        {"detach",  no_argument,       0, 'd'},
        {"help",    no_argument,       0, 'h'},
        {"version", no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };
    int ch;
    while ((ch = getopt_long(argc, argv, "c:dhv", opts, NULL)) != -1) {
        switch (ch) {
        case 'c': config_path = optarg; break;
        case 'd': detach = 1; break;
        case 'v':
            printf("rybaproxy %s (commit %s, built %s)\n", RYBA_VERSION_FULL, RYBA_GIT_COMMIT, RYBA_BUILD_TIME);
            return 0;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 1;
        }
    }

    if (strcmp(cmd, "stop") == 0) return cmd_stop(config_path);
    return cmd_start(config_path, detach);
}
