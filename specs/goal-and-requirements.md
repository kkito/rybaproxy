---
id: ryba-goal
type: goal-and-requirements
status: active
title: rybaproxy 目标与需求
---

## Goal

本地代理网关：对外提供 HTTP / SOCKS5 代理，按规则选择上游出口或直连，可部署在 nginx 之后，并提供 Web 管理与 SQLite 统计。

## Capabilities

- HTTP 代理：普通请求转发与 CONNECT 隧道，hop-by-hop 头处理，可选客户端 Basic 认证。
- SOCKS5 代理：仅 TCP CONNECT（RFC 1928 / 1929）；BIND / UDP_ASSOCIATE 明确拒绝。
- 多上游出口：direct / http / socks5 上游档案，TCP 探测连通性。
- 规则选路：域名、目标 IP/CIDR、端口、协议多条件 AND 匹配，priority 排序；geo 分流（geoip:cn / geosite:cn 及其取反，未知按国外处理）。
- Web 管理：上游与规则 CRUD、会话与统计查询（summary / daily / top）、设置、日志查看、geo 手动下载与检测页。
- 统计持久化：会话明细保留 90 天、日聚合保留 1 年，异步批量写入 SQLite（WAL）。
- 运行形态：前台 / daemon 双模式，pidfile 单实例，SIGHUP 热重载，启动信息屏。

## Non-goals

- 不做 HTTPS MITM / 流量解密；上游仅 TCP（TLS 包裹上游不在范围内）。
- 不做用户级配额计费、集群/多节点同步、IPv6 主动优先。
- 日志无轮转、geo 无增量更新（用户已确认记为约束）。
- 老 `stats.db` 不自动迁移到 `rybaproxy.db`。

## Principles

- TDD 是强制流程：先失败测试再最小实现，收尾 `cmake --build build -j4 && ctest --test-dir build` 全绿。
- 核心判定写成无状态纯函数；状态（锁、缓存、IO）压成最薄胶水。
- 单测零网络：网络边界可注入 mock，空状态短路在网络调用之前，哨兵 mock 锁住漏调。
