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
    config.c/.h          # 配置加载/校验/热重载
    log.c/.h             # 日志
    event_loop.c/.h      # libevent 封装
    queue.c/.h           # 有界队列
    mempool.c/.h         # 内存池（可选）
  net/
    socket.c/.h          # socket 工具、TCP connect、DNS
    tls.c/.h             # 可选 TLS（v2）
  proxy/
    http_proxy.c/.h      # HTTP 代理（CONNECT + 普通请求）
    socks5.c/.h          # SOCKS5
    session.c/.h         # 会话结构、双向 relay
    relay.c/.h           # bufferevent 对接、字节计数
  upstream/
    upstream.c/.h        # 抽象接口
    direct.c/.h          # 直连
    http_upstream.c/.h   # HTTP 代理上游
    socks5_upstream.c/.h # SOCKS5 上游
  router/
    router.c/.h          # 规则匹配引擎
    rules.c/.h           # 规则 CRUD（内存 + DB）
    matcher.c/.h         # 域名/IP/CIDR/端口匹配
  stats/
    stats.c/.h           # 事件采集、聚合
    stats_writer.c/.h    # 异步 SQLite 写入线程
    retention.c/.h       # 3 个月清理
  web/
    httpd.c/.h           # 基于 evhttp 的管理 HTTP 服务
    api.c/.h             # REST 路由
    static.c/.h          # 嵌入式静态资源
  admin/
    auth.c/.h            # token/basic auth
  db/
    sqlite.c/.h          # 连接、迁移、事务
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

- 主线程：libevent 循环（accept、IO、定时器）
- 统计写入线程：从队列取事件，批量事务写入 SQLite
- DNS：使用 libevent `evdns_base`（异步），避免阻塞
- 规则热重载：主线程内原子替换指针（RCU 简化版：新规则表构建完成后 swap，旧表延迟释放）

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
