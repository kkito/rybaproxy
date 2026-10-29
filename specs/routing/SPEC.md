---
id: ryba-routing
type: module-design
status: active
title: 选路与 Geo 分流
parent: ryba-architecture
---

## Responsibility

规则匹配与 geo 判定：输入目标 host/port/协议与 client_ip，输出上游档案选择。判定逻辑为无状态纯函数（`match_domain` / `match_cidr` / geo 三值判定）。

## Boundary

- Owns: `src/router/router.c`、`src/geo/geo.c`（含 dat 解析、SQLite geo 表查询、LRU、DNS 缓存）。
- Input: `rule_t`（domain_pattern、ip_cidr 匹配 client_ip、port、protocol、geo_ip/geo_site）；输出路由 id，下游由 ryba-upstream 换算。
- May use: SQLite geo 表（经 `db_handle` 同一连接）、系统 DNS（经 `geo_set_resolver` 可注入 mock）。

## Decisions

- 多条件 AND，priority 降序、id 升序；无命中走 `default_upstream`。
- `ip_cidr` 匹配的是 client_ip（历史语义，保持不动）；目标 IP 选路由走 `geo_ip`。
- geo 三值语义：`cn` 未知按不满足、`!cn` 未知按满足；私网视为 CN；文件缺失时含 geo 条件规则直接不命中并 WARN 日志，转发不受影响。
- 数据只手动下载（合规可控优先，用户确认），dat 为下载中转、解析后全量覆盖 SQLite；regex 清单留内存。
- 判定 LRU 统一 512 条（`stats.geo_cache_size` 可配，0=关闭，上限 4096）；key 归一化（小写+去尾点）；空库短路在网络调用之前。
