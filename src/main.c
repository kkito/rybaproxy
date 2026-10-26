#include <stdio.h>
#include "rybaproxy/log.h"

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    log_init(LOG_INFO, NULL);
    LOG_INFO("rybaproxy starting (skeleton)");
    return 0;
}
