#ifndef RYBAPROXY_COMMON_H
#define RYBAPROXY_COMMON_H

#include <stdint.h>
#include <stdbool.h>

typedef enum { PROTO_HTTP = 1, PROTO_SOCKS5 = 2 } protocol_t;

#define RYBA_NAME_MAX 128

typedef enum { UPSTREAM_DIRECT=0, UPSTREAM_HTTP=1, UPSTREAM_SOCKS5=2 } upstream_type_t;

typedef struct upstream_profile {
    int id;
    char name[RYBA_NAME_MAX];
    upstream_type_t type;
    char host[256];
    uint16_t port;
    char username[128];
    char password[128];
    int enabled;
} upstream_profile_t;

#endif
