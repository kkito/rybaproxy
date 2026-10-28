# DNS 模块增强 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 `core/dns` 从解析工具函数升级为自包含的 DNS 模块，支持国内/国外分流、多 DoH、以 `1.1.1.1`/`8.8.8.8` IP 直连 DoH 为最终托底及解析国外 DoH 域名的 bootstrap、DNS 专用代理、LRU+TTL 缓存、请求记录以及管理面可观测性（缓存列表 + 请求记录）。

**Architecture:** 在现有 `src/core/dns.c` + `include/rybaproxy/dns.h` 基础上扩展（保留向后兼容）。新增传输层注入、分流（复用 `geo` 的 `geosite`/`geo_ip`）、bootstrap（IP 直连 DoH + Host/SNI，证书校验不可关闭）、代理调度（复用 `upstream` 池）、正向缓存（`dns:v1:{class}:{domain}`）+ 负缓存（`dns:v1:{class}:{resolver_id}:{domain}:neg`，不阻断 fallback）、环形请求记录，并在 `src/web/web_api.c` 暴露管理面 API。网络操作全部走注入，严格遵守单测零网络。

**Tech Stack:** C11, pthread, OpenSSL/libevent（现有依赖）, RFC 8484 (DoH)

## Global Constraints

- 严格遵守项目 TDD：先写失败测试（RED）→最小实现（GREEN）→重构（REFACTOR）。
- **单测零网络**：所有网络调用必须走注入（`dns_set_resolver`、传输层注入）。哨兵 mock 用于锁定零网络。
- 保留向后兼容：`dns_resolve_first`、`dns_getaddrinfo`、`dns_set_resolver`、`dns_set_timeout_sec` 不得破坏现有行为。
- DNS 专用代理：`dns.proxy = "none" | "upstream:<id>"`，复用 `upstream` 池。**托底及用托底解析 DoH 域名时默认走代理**；国内域名默认直连，仅显式配置且确有需要时才允许走代理。
- Bootstrap：**永远不用业务域名的解析链路解析 DoH 域名**。国外 DoH 域名无 `server_ips` 时，优先使用 DoH 配置的 `server_ips` 顺序；用 `1.1.1.1`/`8.8.8.8`（及备用 IP）**IP 直连 DoH**，连接时必须用目标 DoH 的 `Host` 和 TLS SNI，证书校验不可关闭。仅在 fallback IP 全部失败时才允许用 `bootstrap_dns`（传统 DNS）作为**仅限 DoH 域名解析**的例外。
- 最终托底：`https://1.1.1.1/dns-query`、`https://8.8.8.8/dns-query` 仅在**国外域名且全部配置的 DoH 失败**时使用。
- 缓存：LRU 容量 1024。正向缓存 key `dns:v1:{class}:{domain}`。负缓存 key `dns:v1:{class}:{resolver_id}:{domain}:neg`，TTL 10~60s。TTL clamp（60s~1800s）。**负缓存命中不阻断切换到下一个 resolver 或 fallback**。
- 请求记录：环形缓冲区（默认 256），倒序查询。管理相关 API 主要供 Web 界面内部使用。
- 核心对外查询以 `dns_resolve` 为主，保留 `dns_resolve_first`/`dns_getaddrinfo`。
- 每个任务结束需保证 `cmake --build build -j4 && ctest --test-dir build` 全绿。

**Spec:** `docs/superpowers/specs/2026-10-28-dns-module-enhancement-design.md`

---

## Task 1: 扩展接口、数据结构与配置桩（TDD）
**Files:**
- Modify: `include/rybaproxy/dns.h`
- Modify: `src/core/dns.c`
- Add/Modify: `tests/unit/test_dns.c`
- Modify: `include/rybaproxy/config.h`（如需扩展，向后兼容）

### Steps
- [ ] **1.1 RED** 在 `tests/unit/test_dns.c` 添加接口存在性测试（`dns_resolve`、`dns_set_proxy`、`dns_set_nameservers`/`add/clear`、`dns_cache_list/count/flush`、`dns_log_list/count/clear`）。
- [ ] **1.2 验证失败** 编译/运行相关测试确认失败。
- [ ] **1.3 实现** 扩展 `dns.h`（`dns_class_t`、`dns_ns_t`、`dns_cache_entry_t`、`dns_req_log_t`、`dns_result_t` 等）并添加桩实现，保留所有旧接口。
- [ ] **1.4 GREEN** 编译通过，测试转绿。
- [ ] **1.5 提交** `git commit -m "feat(dns): extend dns interfaces and structs for enhanced module"`

---

## Task 2: LRU + TTL clamp + 正向/负缓存（TDD）
**Files:**
- Modify: `src/core/dns.c`
- Modify: `tests/unit/test_dns.c`

### Steps
- [ ] **2.1 RED** 测试：容量 1024 LRU 淘汰；正向 key `dns:v1:{class}:{domain}`；负缓存 key `dns:v1:{class}:{resolver_id}:{domain}:neg`；TTL clamp（60s~1800s）；负缓存 TTL（10~60s）；**负缓存不阻断切换 resolver/fallback**。
- [ ] **2.2 验证失败** 运行测试确认 RED。
- [ ] **2.3 实现** 带锁 LRU、正向/负缓存隔离、clamp 逻辑。
- [ ] **2.4 GREEN** 测试通过。
- [ ] **2.5 提交** `git commit -m "feat(dns): add LRU with separated positive/negative cache and ttl clamp"`

---

## Task 3: 国内/国外分流与 IP 字面量直返（TDD）
**Files:**
- Modify: `src/core/dns.c`
- Modify: `tests/unit/test_dns.c`

### Steps
- [ ] **3.1 RED** 测试：域名归一化、`geosite` 分流 domestic/foreign、IP 字面量直返（不触发 DNS）。
- [ ] **3.2 验证失败** 确认 RED。
- [ ] **3.3 实现** 复用 `geo_site_is_cn` 等逻辑，分流后置于缓存查找之前？按 spec：**缓存查找在分流前**，命中直接返回。
- [ ] **3.4 GREEN** 测试通过。
- [ ] **3.5 提交** `git commit -m "feat(dns): add split and IP literal bypass with cache-before-split"`

---

## Task 4: 传输层抽象与 DoH 基础（注入，零网络）
**Files:**
- Add/Modify: `src/core/dns_doh.c`（或 `src/core/dns.c`）
- Modify: `include/rybaproxy/dns.h`
- Modify: `tests/unit/test_dns.c`

### Steps
- [ ] **4.1 RED** 测试：注入 transport，断言调用参数（method/url/headers/body），不发真实请求。
- [ ] **4.2 验证失败** 确认 RED。
- [ ] **4.3 实实现** 定义传输接口，预留 RFC 8484（POST `application/dns-message`、GET base64url）。
- [ ] **4.4 GREEN** 测试通过。
- [ ] **4.5 提交** `git commit -m "feat(dns): add injectable doh transport layer"`

---

## Task 5: Bootstrap（IP 直连 DoH）及用托底解析国外 DoH 域名（TDD）
**Files:**
- Modify: `src/core/dns.c`
- Modify: `src/core/dns_doh.c`
- Modify: `tests/unit/test_dns.c`

### Steps
- [ ] **5.1 RED** 测试：国外 DoH 无 `server_ips` -> 用 `1.1.1.1`/`8.8.8.8` IP 直连，断言 `Host` 和 TLS SNI 为目标 `doh_host`，证书校验流程被调用；尝试 `server_ips` 顺序和 fallback IP 顺序；用哨兵验证**不用业务域名链路**解析 DoH 域名；仅当 fallback IP 全部失败时才可用 `bootstrap_dns`（仅限 DoH 域名解析）。
- [ ] **5.2 验证失败** 确认 RED。
- [ ] **5.3 实现** 严格按 bootstrap 流程实现。
- [ ] **5.4 GREEN** 测试通过。
- [ ] **5.5 提交** `git commit -m "feat(dns): ip-direct doh bootstrap with host/sni and cert validation"`

---

## Task 6: 国内外查询路径、DNS 专用代理、最终托底（TDD）
**Files:**
- Modify: `src/core/dns.c`
- Modify: `src/upstream/upstream.c`（最小改动，复用接口)
- Modify: `tests/unit/test_dns.c`

### Steps
- [ ] **6.1 RED** 测试：国内走国内 nameserver（默认直连，仅显式允许时走代理）、国外 DoH 列表失败 -> 最终托底（1.1.1.1/8.8.8.8 IP 直连 DoH）；托底及 bootstrap 用托底解析 DoH 域名时若 `dns.proxy` 配置则走代理；代理失败按顺序 fallback；**负缓存不阻断切换**。
- [ ] **6.2 验证失败** 确认 RED。
- [ ] **6.3 实现** 按流程图实现国内外分支，复用 `upstream` 隧道。
- [ ] **6.4 GREEN** 测试通过。
- [ ] **6.5 提交** `git commit -m "feat(dns): domestic/foreign paths, dns-specific proxy, ip-doh fallback"`

---

## Task 7: 请求记录（环形缓冲区，TDD）
**Files:**
- Modify: `src/core/dns.c`
- Modify: `tests/unit/test_dns.c`

### Steps
- [ ] **7.1 RED** 测试：环形覆盖、时间倒序、字段齐全（`ts/domain/class/resolver_id/via_proxy/duration_ms/status/ip_count/from_cache`）、清空。
- [ ] **7.2 验证失败** 确认 RED。
- [ ] **7.3 实现** 环形缓冲区（默认 256，可配）。
- [ ] **7.4 GREEN** 测试通过.
- [ ] **7.5 提交** `git commit -m "feat(dns): add ring-buffer request log"`

---

## Task 8: 管理面 API（Web，TDD）
**Files:**
- Modify: `src/web/web_api.c`
- Modify: `include/rybaproxy/dns.h`
- Modify: `tests/unit/test_web_api.c`

### Steps
- [ ] **8.1 RED** 测试：缓存列表、请求记录列表、`dns_cache_flush`、`dns_log_clear`。
- [ ] **8.2 验证失败** 确认 RED。
- [ ] **8.3 实现** 管理端点（主要供 Web 界面内部使用），调用 `dns_cache_list/dns_log_list/dns_cache_flush/dns_log_clear`。
- [ ] **8.4 GREEN** 测试通过。
- [ ] **8.5 提交** `git commit -m "feat(web): expose dns cache and request log to management api"`

---

## Task 9: 配置接入、集成与全量验证
**Files:**
- Modify: `src/core/config.c`
- Modify: `include/rybaproxy/config.h`
- Modify: `src/main.c`
- Modify: `src/geo/geo.c`、`src/router/router.c`（仅必要时）

### Steps
- [ ] **9.1 配置** 解析 `dns` 段（proxy/nameservers/bootstrap_dns/fallback/cache_size/log_size/TTL clamp 配置），全默认值向后兼容。
- [ ] **9.2 初始化** `main.c` 接入配置并初始化 DNS 模块。
- [ ] **9.3 集成** 确保现有 `geo/router/upstream/web` 无回归，收拢 `getaddrinfo` 至 `core/dns`（必要时）。
- [ ] **9.4 全量验证** `cmake --build build -j4 && ctest --test-dir build` 全绿。
- [ ] **9.5 提交** `git commit -m "feat(dns): wire config and integrate enhanced dns module"`

---

## 执行说明
- 严格 TDD，零网络约束。
- 遵循 AGENTS.md。
- 按 spec 流程图实现，重点关注 bootstrap、负缓存不阻断、DNS 专用代理策略、证书校验。
