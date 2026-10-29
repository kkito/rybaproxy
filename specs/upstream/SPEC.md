---
id: ryba-upstream
type: module-design
status: active
title: 上游出口
parent: ryba-architecture
---

## Responsibility

出站拨号：direct 直连、经 HTTP 代理、经 SOCKS5 代理的三路 `upstream_connect_*`，以及统一的 TCP 可达探测。

## Boundary

- Owns: `src/upstream/upstream.c`。
- Input: 路由选出的上游档案；`upstream_pick` 为纯函数（route_id < 0 表无命中）。
- Never: 解析规则、访问 DB。

## Decisions

- `test` 接口只做 TCP connect 探测（3s 超时），direct 恒返回可达；不可达回 200 + `reachable:false`，不抛 500。
- 上游仅 TCP；TLS 包裹上游不在范围（见 goal 非目标）。
