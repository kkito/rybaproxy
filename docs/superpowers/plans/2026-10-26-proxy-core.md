# Proxy Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Proxy Core: HTTP proxy (CONNECT + normal requests), SOCKS5 CONNECT, direct/HTTP/SOCKS5 upstreams, client Basic auth, relay, v1 routing, in-memory stats, with full tests.

**Architecture:** libevent event loop + bufferevent; llhttp for HTTP parsing; c-ares DNS; civetweb reserved for later web subproject. State machines for SOCKS5 and upstream handshakes. Unified session structure.

**Tech Stack:** C11, libevent, OpenSSL, SQLite3 (linked now, used later), cJSON, llhttp, c-ares, cmocka, vcpkg.

## Global Constraints

- C standard: C11, `-Wall -Wextra -Wpedantic`
- Dependencies via vcpkg only (`vcpkg.json`)
- Build via CMake + Makefile wrapper
- Tests must pass under ASan/UBSan/TSan
- No dynamic SQL yet (SQLite reserved for stats subproject)
- All public headers under `include/rybaproxy/`

---

## File Structure

Create:
- `include/rybaproxy/common.h`
- `include/rybaproxy/config.h`, `src/core/config.c`
- `include/rybaproxy/session.h`, `src/proxy/session.c`
- `include/rybaproxy/router.h`, `src/router/router.c`
- `include/rybaproxy/auth.h`, `src/admin/auth.c`
- `include/rybaproxy/socks5.h`, `src/proxy/socks5.c`
- `include/rybaproxy/http_proxy.h`, `src/proxy/http_proxy.c`
- `include/rybaproxy/upstream.h`, `src/upstream/upstream.c`, `direct.c`, `http_upstream.c`, `socks5_upstream.c`
- `include/rybaproxy/relay.h`, `src/proxy/relay.c`
- `include/rybaproxy/server.h`, `src/proxy/server.c`
- `include/rybaproxy/stats.h`, `src/stats/stats.c`
- Tests under `tests/unit/` and `tests/integration/`

---

### Task 1: Common types and config

**Files:**
- Create: `include/rybaproxy/common.h`
- Create: `include/rybaproxy/config.h`
- Create: `src/core/config.c`
- Test: `tests/unit/test_config.c`

**Interfaces:**
- Produces: `config_t`, `config_load(const char*, config_t*)`, `config_free(config_t*)`

- [ ] **Step 1: Write failing test**

```c
// tests/unit/test_config.c
#include <cmocka.h>
#include "rybaproxy/config.h"

static void test_config_defaults(void **state) {
    (void)state;
    config_t c;
    config_init_defaults(&c);
    assert_int_equal(c.http_port, 8080);
    assert_int_equal(c.socks5_port, 1080);
    assert_true(c.fallback_to_direct);
}
int main(void) {
    const struct CMUnitTest tests[] = { cmocka_unit_test(test_config_defaults) };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
```

- [ ] **Step 2: Run test (expect fail)**

Run: `cmake --build build 2>&1 | tail; ctest --test-dir build -R config 2>&1 | tail`
Expected: FAIL (undefined references)

- [ ] **Step 3: Implement minimal config**

```c
// include/rybaproxy/common.h
#ifndef RYBAPROXY_COMMON_H
#define RYBAPROXY_COMMON_H
#include <stdint.h>
#include <stdbool.h>
typedef enum { PROTO_HTTP=1, PROTO_SOCKS5=2 } protocol_t;
#endif
```

```c
// include/rybaproxy/config.h
#ifndef RYBAPROXY_CONFIG_H
#define RYBAPROXY_CONFIG_H
#include "rybaproxy/common.h"
typedef struct {
    int http_port;
    int socks5_port;
    int max_connections;
    int idle_timeout_sec;
    int max_session_sec;
    int connect_timeout_sec;
    bool proxy_auth_enabled;
    char proxy_username[128];
    char proxy_password[128];
    char default_upstream[64];
    bool fallback_to_direct;
    bool resolve_for_routing;
} config_t;
void config_init_defaults(config_t *c);
int config_load(const char *path, config_t *c);
void config_free(config_t *c);
#endif
```

```c
// src/core/config.c
#include "rybaproxy/config.h"
#include <string.h>
void config_init_defaults(config_t *c) {
    memset(c, 0, sizeof *c);
    c->http_port = 8080;
    c->socks5_port = 1080;
    c->max_connections = 10240;
    c->idle_timeout_sec = 300;
    c->max_session_sec = 3600;
    c->connect_timeout_sec = 10;
    strcpy(c->default_upstream, "direct");
    c->fallback_to_direct = true;
}
int config_load(const char *path, config_t *c) {
    config_init_defaults(c);
    // cJSON parse (omitted for brevity in plan; implement full in code)
    return 0;
}
void config_free(config_t *c) { (void)c; }
```

- [ ] **Step 4: Run test (expect pass)**

Run: `make build && ctest --test-dir build -R config --output-on-failure`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add include/rybaproxy/common.h include/rybaproxy/config.h src/core/config.c tests/unit/test_config.c CMakeLists.txt
git commit -m "feat: add common types and config"
```

---

### Task 2: Session structure

**Files:**
- Create: `include/rybaproxy/session.h`
- Create: `src/proxy/session.c`
- Test: `tests/unit/test_session.c`

**Interfaces:**
- Produces: `session_t`, `session_create(...)`, `session_destroy(...)`

- [ ] Write failing test for session byte counters
- [ ] Implement session with `bytes_up`, `bytes_down`, `started_at`, `ended_at`
- [ ] Commit

---

### Task 3: Router v1

**Files:**
- Create: `include/rybaproxy/router.h`, `src/router/router.c`
- Test: `tests/unit/test_router.c`

**Interfaces:**
- `int router_select(const router_t*, const char *host, int port, protocol_t proto, const char *client_ip)`

- [ ] Tests: default upstream, domain suffix, port filter
- [ ] Implement O(n) rule scan with priority
- [ ] Commit

---

### Task 4: Auth

**Files:**
- Create: `include/rybaproxy/auth.h`, `src/admin/auth.c`
- Test: `tests/unit/test_auth.c`

- [ ] Base64 decode + Basic compare (constant-time)
- [ ] Commit

---

### Task 5: SOCKS5 state machine

**Files:**
- Create: `include/rybaproxy/socks5.h`, `src/proxy/socks5.c`
- Test: `tests/unit/test_socks5.c`

- [ ] Parse handshake, method selection, RFC1929 auth, CONNECT request (IPv4/domain/IPv6)
- [ ] Reject BIND/UDP
- [ ] Commit

---

### Task 6: HTTP proxy parsing

**Files:**
- Create: `include/rybaproxy/http_proxy.h`, `src/proxy/http_proxy.c`
- Test: `tests/unit/test_http_proxy.c`

- [ ] Use llhttp to parse request line, headers, detect CONNECT vs normal
- [ ] Extract target host/port
- [ ] Commit

---

### Task 7: Upstream connectors

**Files:**
- Create: `include/rybaproxy/upstream.h`, `src/upstream/upstream.c`, `direct.c`, `http_upstream.c`, `socks5_upstream.c`
- Test: `tests/unit/test_upstream.c`

- [ ] Unified `upstream_connect`
- [ ] HTTP upstream CONNECT handshake
- [ ] SOCKS5 upstream handshake
- [ ] Commit

---

### Task 8: Relay

**Files:**
- Create: `include/rybaproxy/relay.h`, `src/proxy/relay.c`
- Test: `tests/unit/test_relay.c`

- [ ] bufferevent pair, byte counters, timeouts, cleanup
- [ ] Commit

---

### Task 9: Server/listener

**Files:**
- Create: `include/rybaproxy/server.h`, `src/proxy/server.c`
- Modify: `src/main.c`

- [ ] Accept connections, create sessions, wire protocols
- [ ] Graceful shutdown on SIGTERM
- [ ] Commit

---

### Task 10: Stats v1

**Files:**
- Create: `include/rybaproxy/stats.h`, `src/stats/stats.c`
- Test: `tests/unit/test_stats.c`

- [ ] Atomic counters, session_event_t, queue (in-memory)
- [ ] Commit

---

### Task 11: Integration tests

**Files:**
- Create: `tests/integration/test_proxy_http.sh`
- Create: `tests/integration/test_proxy_socks5.sh`
- Create: `tests/integration/mock_upstream.py`

- [ ] End-to-end HTTP/CONNECT/SOCKS5
- [ ] Upstream chaining
- [ ] Commit

---

### Task 12: Hardening

- [ ] Run `make asan ubsan tsan` and fix
- [ ] clang-tidy/cppcheck clean
- [ ] Update docs

---

## Self-Review Checklist

- Spec coverage: all Proxy Core requirements mapped to tasks
- No placeholders in final code
- Type consistency across tasks

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-26-proxy-core.md`.

Two execution options:

1. Subagent-Driven (recommended) - fresh subagent per task + two-stage review
2. Inline Execution - execute tasks in this session using executing-plans

Which approach?
