---
id: ryba-persist
type: module-design
status: active
title: 持久化与统计
parent: ryba-architecture
---

## Responsibility

SQLite 持久化与统计查询：会话明细、规则/上游表、settings、日聚合、保留清理；数据面经有界队列异步批量写入。

## Boundary

- Owns: `src/db/db.c`、`src/stats/stats.c`；库文件默认 `<数据目录>/rybaproxy.db`。
- Readers: ryba-web（只读聚合查询）、ryba-routing（geo 表经 `db_handle`）。
- Writers: 仅后台写线程持有写连接。

## Decisions

- WAL 模式；明细保留 90 天、日聚合保留 1 年；队列满丢最旧并计 `dropped_events`，不阻塞数据面。
- from/to 统一 unix ms；daily 按天聚合是 heatmap 与今日流量的唯一口径。
- geo 表（`geo_ip`/`geo_ip6`/`geo_site_exact`/`geo_site_suffix`）与 stats 同库，只入库 CN 条目；regex 留内存。
- 老 `stats.db` 不自动迁移（用户确认的约束）。
