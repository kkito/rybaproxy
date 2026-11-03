---
id: ryba-architecture
type: architecture-design
status: active
title: rybaproxy 架构
parent: ryba-goal
---

# 架构

## 1. 总体设计

- **事件驱动**：单进程、单事件循环（libevent）+ 非阻塞 socket。高并发连接通过 `bufferevent` 转发。
- **数据面**与**控制面**分离：
  - 数据面：代理转发热路径，不访问 SQLite。
  - 控制面：Web/REST、规则管理、统计写入，通过内存队列与数据面解耦。
- **统计写入**：数据面把"会话结束事件"压入无锁/互斥队列；独立写入线程批量 `INSERT` SQLite。

## 2. 模块划分

```
src/
  main.c                 # 入口、信号、启动
  core/
    config.c             # 配置加载/校验
    log.c                # 分级日志（trace..fatal）
    reqlog.c             # 单条请求日志的纯格式化（路由/连接/结束三行）
    dns.c                # getaddrinfo 封装（可注入 resolver，单测零网络）
    strutil.c            # 字符串/大小写查找工具
    daemon.c             # 后台化
    pidfile.c            # pid 文件
    startup_info.c       # 启动横幅
  net/
    connpool.c           # 连接线程池：把阻塞的 DNS/connect/握手搬出事件循环
  geo/
    geo.c                # geoip/geosite 判定 + LRU 缓存（键按语义分前缀）
  proxy/
    server.c             # 监听、accept、路由决策、异步连上游、日志胶水
    http_proxy.c         # HTTP 请求行/头解析（纯函数）
    socks5.c             # SOCKS5 报文解析与应答构造（纯函数）
    session.c            # 会话结构、结算语义
    relay.c              # 双向 relay（bufferevent）、字节计数
  upstream/
    upstream.c           # direct/HTTP CONNECT/SOCKS5 建连与握手 + 路由落地（纯函数）
  router/
    router.c             # 规则匹配引擎（含 geo 条件、诊断信息 router_select_ex）
  stats/
    stats.c              # 事件采集、聚合、异步 SQLite 写入
  web/
    web.c                # civetweb 管理 HTTP 服务
    web_api.c            # REST 路由（含 /api/geo/check）
  admin/
    auth.c               # Basic/代理认证
  db/
    db.c                 # SQLite 连接、迁移、批量写入
tests/
  unit/ ...
  integration/ ...
third_party/
  cJSON.c/.h
  unity/ (测试框架)
```

## 3. 关键数据结构

### 3.1 Session

```c
typedef struct session {
    uint64_t id;
    int      protocol;        // PROTO_HTTP / PROTO_SOCKS5
    char     client_ip[64];
    char     target_host[256];
    uint16_t target_port;
    char     method[16];       // HTTP method or "CONNECT"/"SOCKS5"
    int      upstream_id;     // 选择的上游档案 id
    int      status;          // 0=active 1=done 2=error
    int      error_code;
    uint64_t bytes_up;
    uint64_t bytes_down;
    int64_t  started_at;      // unix ms
    int64_t  ended_at;
    // libevent
    struct bufferevent *bev_client;
    struct bufferevent *bev_upstream;
    struct event *timeout_ev;
} session_t;
```

### 3.2 Upstream Profile

```c
typedef struct upstream_profile {
    int    id;
    char   name[64];
    int    type;        // DIRECT/HTTP/SOCKS5
    char   host[256];
    uint16_t port;
    char   username[128];
    char   password[128];
    int    enabled;
    // 统计
    uint64_t total_sessions;
    uint64_t total_bytes_up;
    uint64_t total_bytes_down;
} upstream_profile_t;
```

### 3.3 Rule

```c
typedef struct rule {
    int    id;
    int    priority;        // 越大越优先
    int    enabled;
    char   name[64];
    // 匹配条件（空表示不限制）
    char   domain_pattern[256];   // 支持 *.example.com / exact
    char   ip_cidr[64];           // e.g. 10.0.0.0/8
    int    port;                  // 0=any
    int    protocol;              // 0=any
    int    upstream_id;
} rule_t;
```

## 4. 数据流

### 4.1 HTTP 代理普通请求

1. 客户端发送 `GET http://host/path HTTP/1.1`
2. `http_proxy` 解析请求行与 Host
3. router 选择 upstream
4. 若 upstream=direct/http/socks5：建立到目标（或上游）连接
   - direct: 连接 target host:port，转发 HTTP 请求
   - http upstream: 发送 `GET ...` 到上游代理
   - socks5 upstream: 通过上游 SOCKS5 CONNECT target，再转发
5. 双向 relay，计数
6. 会话结束 -> stats 事件

### 4.2 HTTP CONNECT

1. `CONNECT host:port HTTP/1.1`
2. 选择 upstream
3. 建立到 target 的隧道（经 upstream）
4. 回 `200 Connection Established`
5. 双向 relay

### 4.3 SOCKS5

标准 RFC 1928：协商方法 -> (可选用户名密码 RFC 1929) -> CONNECT/BIND/UDP_ASSOCIATE。v1 仅支持 CONNECT（TCP），BIND/UDP 记为不支持并返回拒绝。

### 4.4 Nginx 模式

- nginx 将请求转发到网关的 HTTP 代理端口或专用端口。
- 网关从 `X-Forwarded-For` 取真实客户端 IP（可信代理列表控制）。
- 路由仍按目标 host/ip 选择 upstream，与直连一致。
- 对 nginx 透明：网关可返回标准 HTTP 响应；CONNECT 在 nginx 后面通常不走 nginx（nginx 不支持 CONNECT 代理），因此 "nginx 后面" 主要针对普通 HTTP 转发与管理/统计，CONNECT 直连端口单独暴露。文档明确此限制。

## 5. 并发与线程

- **主线程**：libevent 循环（accept、IO、超时、事件泵），**不做任何阻塞调用**。
- **连接线程池**（`src/net/connpool.c`，默认 32 线程）：执行**路由判定 + 建连**整段阻塞活
  ——geo 判定里的 DNS 解析（`geo_host_is_cn` → `getaddrinfo`）、TCP connect、
  HTTP `CONNECT` / SOCKS5 握手；干完把 fd 通过 socketpair 交回主线程。
  规则/上游表在锁内**拷贝快照**后立刻放锁，DNS 不持锁（否则工作线程会互相排队）。
  > 为什么必须有它：这些调用原先直接跑在事件循环里，一个慢连接会把所有并发请求串行卡住
  > （实测 10 个 3s 的坏目标能让无关请求排队 15s）。
- **统计写入线程**：从队列取会话事件，批量事务写入 SQLite。
- **超时**：`limits.connect_timeout_sec` 同时用于 connect 和握手（握手期设
  `SO_RCVTIMEO`，避免"接了 TCP 却不回应答"的上游把工作线程占死）；`limits.idle_timeout_sec`
  用 bufferevent 超时实现，断掉的会话不会永远停在 ACTIVE。
- **缓存**：geo 的 LRU 键按语义分前缀（`ip:` / `host:` / `site:` / `lan:`），
  **不同语义不得共用一个键**（曾因 `geo_site_is_cn` 与 `geo_host_is_cn` 都用 `host:`
  导致国内 IP 域名被误判走代理）。
- 规则热重载：主线程内原子替换指针（RCU 简化版：新规则表构建完成后 swap，旧表延迟释放）。

## 6. 资源与限制

- 最大连接数：配置项 `max_connections`，默认 10240
- 单连接缓冲：bufferevent high/low watermark
- 空闲超时：`idle_timeout_sec` 默认 300
- 连接总超时：`max_session_sec` 默认 3600

## 7. 错误处理

- 所有系统调用检查返回值
- 连接失败：向客户端返回 502/504 或 SOCKS5 失败码
- 上游不可用：按规则 fallback（可配置 `fallback_to_direct`）
- 统计写入失败：记录日志，不阻塞数据面；队列满时丢弃最旧事件并计数 `dropped_events`

## 8. 请求日志（排障用）

每个请求默认打三行（`log_level: debug` 起才含"连接"行；路由与结束行是 `info`），
格式由 `src/core/reqlog.c` 的纯函数生成，方便 grep：

```
[42] 路由 host=www.bing.com:443 proto=HTTP method=CONNECT client=192.168.1.5 \
     rule=3/cn-ip-direct upstream=direct geo=site:0,ip:1,lan:0
[42] 连接 upstream=direct ok ms=44
[42] 结束 host=www.bing.com:443 status=ok dur=0ms up=998 down=8752
```

- `rule=<id>/<名字>`：命中的规则；`-/default` 表示没规则命中、走了默认上游。
- `geo=site:x,ip:y,lan:z`：这次实际查到的 geo 结果，`-` 表示**没查**（不是"不是"）。
- 失败时多一行 `失败 ... reason=<原因> -> <状态码>`，并且结束行会带 `err=`。
- 想追一个请求：`grep '\[42\]' rybaproxy.log`。
