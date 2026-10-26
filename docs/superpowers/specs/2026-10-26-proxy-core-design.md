# Proxy Core 设计（子项目 1）

日期：2026-10-26  
状态：已获用户批准（brainstorming）

## 1. 范围

子项目 1 交付一个**可用的代理核心**，支持：

- HTTP 代理：`CONNECT` 隧道与普通 HTTP 请求（GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS）
- SOCKS5：CONNECT（TCP）
- 上游：direct、HTTP 代理、SOCKS5 代理
- 客户端到网关的 Proxy Basic 认证（可配置开关）
- 基础内存计数器与会话事件结构（SQLite 持久化留子项目 3）

不包含：完整规则引擎（子项目 2）、Web 管理（子项目 4）、nginx 集成（子项目 5）、TLS 包裹上游（v2）。

## 2. 架构

事件驱动：libevent 事件循环 + bufferevent，单进程。DNS 使用 c-ares（或 libevent evdns 作为 fallback）。HTTP 解析使用 llhttp。

## 3. 组件

- `listener`：HTTP 端口与 SOCKS5 端口 accept，创建 session
- `session`：持有 client/upstream bufferevent、计数、超时定时器、状态
- `http_proxy`：llhttp 解析；CONNECT 与普通请求分支；hop-by-hop 头处理
- `socks5`：RFC 1928/1929 状态机；仅 CONNECT
- `upstream`：统一接口 `upstream_connect(session, target_host, target_port)`，实现 direct/http/socks5
- `relay`：双向 bufferevent 转发、字节计数、空闲超时
- `router_v1`：默认 upstream + 简单域名后缀/端口匹配
- `auth`：Proxy-Authorization Basic 校验
- `stats_v1`：内存原子计数器 + `session_event_t` 结构

## 4. 数据流

1. accept → session_create → 协议握手
2. 解析目标 host/port
3. router_v1 选 upstream → upstream_connect
4. 成功：HTTP CONNECT 返回 200；SOCKS5 返回成功响应；普通 HTTP 转发请求
5. relay 双向转发并计数
6. 关闭：更新计数、填充 session_event_t（供后续持久化）

## 5. 错误处理

- 连接/握手失败：HTTP 返回 502/504；SOCKS5 返回对应 rep 码
- 解析失败：立即关闭，计 `bad_requests`
- 上游不可用：若配置 `fallback_to_direct`，重试 direct
- 超时：`idle_timeout_sec` / `max_session_sec`

## 6. 并发与资源

- 最大连接数 `max_connections`
- bufferevent 水位与超时
- 非阻塞 DNS

## 7. 测试

- 单元：llhttp 解析、SOCKS5 状态机、upstream 握手、router_v1、auth
- 集成：curl HTTP/CONNECT/SOCKS5、mock 上游、错误路径、超时
- Sanitizer：ASan/UBSan/TSan 全量

## 8. 验收标准

- `curl -x http://127.0.0.1:8080 http://example/` 成功
- `curl -x http://127.0.0.1:8080 -p https://example/` 隧道成功
- `curl --socks5 127.0.0.1:1080 https://example/` 成功
- 上游 HTTP/SOCKS5 代理链路成功
- `make asan`/`ubsan`/`tsan` 全绿
