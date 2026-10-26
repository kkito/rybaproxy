#include "rybaproxy/config.h"
#include "rybaproxy/log.h"
#include "rybaproxy/server.h"
#include "rybaproxy/stats.h"

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

int main(int argc, char **argv) {
    const char *config_path = NULL;
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            printf("rybaproxy 0.1.0\n");
            return 0;
        }
    }
    log_init(LOG_INFO, NULL);
    stats_init();

    config_t cfg;
    config_init_defaults(&cfg);
    if (config_path) {
        if (config_load(config_path, &cfg) != 0) {
            LOG_ERROR("failed to load config: %s", config_path);
            return 1;
        }
    }

    g_srv = calloc(1, sizeof *g_srv);
    if (server_init(g_srv, &cfg) != 0) {
        LOG_ERROR("server_init failed");
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    LOG_INFO("rybaproxy listening http=%d socks5=%d", cfg.http_port, cfg.socks5_port);
    server_run(g_srv);

    server_free(g_srv);
    config_free(&cfg);
    free(g_srv);
    LOG_INFO("shutdown");
    return 0;
}
