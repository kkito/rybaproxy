---
id: ryba-proxy
type: module-design
status: active
title: 代理数据面（HTTP/SOCKS5）
parent: ryba-architecture
---

## Responsibility

客户端接入与字节转发热路径：HTTP 普通请求 / CONNECT 隧道、SOCKS5 CONNECT、双向 relay 与会话生命周期。不访问 SQLite。

## Boundary

- Owns: `src/proxy/`（server、http_proxy、socks5、session、relay）、客户端 Proxy Basic 认证（`src/admin/auth.c`）。
- May use: ryba-routing（选路）、ryba-upstream（出口拨号）、内存 stats 计数器。
- Never: 直连 SQLite；DNS 解析只经 geo 注入的 resolver（单测零网络）。

## Decisions

- 单进程单事件循环（libevent）+ bufferevent 转发；DNS 用 c-ares，HTTP 解析用 llhttp。
- SOCKS5 仅 CONNECT；BIND / UDP 返回 0x07/0x08 拒绝。
- CONNECT 在 nginx 后面需 `stream` 透传——nginx 不做 CONNECT 代理（用户确认的已知局限）。
- 上游失败按 `fallback_to_direct` 回退 direct；隧道建立后不重试。
- 错误映射：HTTP 502/504，SOCKS5 对应 rep 码；解析失败直接关闭并计 `bad_requests`。
