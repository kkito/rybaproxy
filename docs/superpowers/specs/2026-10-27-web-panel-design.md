# Web 管理面板完善 — 设计文档（B 档）

日期：2026-10-27 · 范围：对齐 docs/design/ui-redesign.html + docs/web-api.md（B 档：完整 API，不做 SSE/Auth，用轮询）

## 1. 决策记录

- 数据接线范围：B（完整对齐 web-api.md，heatmap 真实数据）
- 上游编辑+测试：A（PUT 编辑 + 真实 TCP 探测 test）
- Heatmap/今日流量口径：A（纯 SQLite 聚合，`GET /api/stats/daily?days=30` 唯一口径）
- 实时刷新：B（`setInterval(fetch, 5s)` 轮询，不做 SSE）
- 实现方案：方案一（原地扩展 `src/web/web.c`，拆分为 `web_api.c` / `web_page.h`）

## 2. 后端 API 设计

### 2.1 保留 + 别名

- `GET /api/stats` 保留（兼容），新增 `GET /api/metrics` 同义。
- 保留 `GET/POST/DELETE /api/upstreams`、`GET/POST/PUT/DELETE /api/rules`、`GET /api/sessions`。

### 2.2 新增接口

- `GET /healthz` -> `{ok:true,data:{status:"ok",version:"..."}}`（无鉴权）。
- `PUT /api/upstreams/:id`：body `{name,type,host,port,enabled}` 部分更新；query 兼容 `?id=`。
- `POST /api/upstreams/:id/test`：非阻塞 connect + 3s 超时探测 direct/http/socks5，
  返回 `{ok:true,data:{reachable:bool,latency_ms:int}}`；不可达返回 reachable=false（200，非 500）。
- `POST /api/rules/reload`：按 priority 重排内存规则，返回 `{ok:true}`。
- `GET /api/sessions?client=&target=&upstream=&limit=&offset=` -> `{data:[...],total,limit,offset}`；
  `GET /api/sessions/:id` -> 单条或 404。
- `GET /api/stats/summary?from=&to=`（unix ms）：`{sessions,bytes_up,bytes_down,errors}`。
- `GET /api/stats/daily?days=30`：`[{day:"YYYY-MM-DD",sessions,bytes_up,bytes_down,errors}]`，
  SQL：`SELECT date(started_at/1000,'unixepoch') ... GROUP BY day`；heatmap + 今日流量唯一口径。
- `GET /api/stats/top?by=target|client&limit=20&from=&to=`。
- `GET /api/settings` / `PUT /api/settings`（retention 等，落 settings 表）。
- `GET /api/logs?level=&limit=`（环形内存日志）。

### 2.3 信封与错误码

- 成功：`{ok:true,data:...}`；列表分页：`{ok:true,data:[...],total,limit,offset}`。
- 失败：`{ok:false,error:{code,message}}`；bad json->400，id 不存在->404，DB 失败->500。

### 2.4 内存态与 DB 双写

- 启动从 DB 加载 upstreams/rules；写操作同步落库 + 更新 `server_ctx` 内存（持 lock）。
- sessions/summary/daily/top 读走 SQLite 只读查询；metrics 走内存 stats 计数器。

## 3. 前端设计（INDEX_HTML 内 JS 重写，CSS 不动）

- 删除全部 mock 数组；新增 `api(path, opts)` 统一 fetch + 错误 toast。
- `loadAll()` 并行拉 upstreams/rules/sessions(limit 20)/metrics/summary/daily。
- Hero：活跃会话（metrics）+ 今日上/下（daily 最后一项）+ 错误/丢弃；sparkline 用 daily 真实 30 点。
- 上游表行操作：启用/停用 + 编辑（复用弹窗）+ 测试（显示 latency）+ 删除（confirm）。
- 规则表：add/edit 共用弹窗 + 校验（域名/IP 至少一项、priority 数字、upstream_id 存在）。
- 会话表：5s 轮询 + client/target 过滤；heatmap 30 格真实日期+MB tooltip，无数据灰色空态。
- 保留时钟/toast/confirm/modal；初载用 `.skel` 骨架屏。

## 4. 数据流

proxy session 结束 -> stats 计数器 + db_enqueue -> 写线程落库 -> Web 读。
daily 按天聚合，from/to 为 unix ms。

## 5. 测试计划（cmocka，全覆盖目标）

- 现有 8 个测试保持通过。
- 新增 `tests/unit/test_web_api.c`：每个 handler 的 200/400/404、信封格式、分页 total、
  daily 聚合（含空库/跨天）、upstream test 超时分支、settings/logs。
- 扩展 `test_db.c`：sessions 过滤分页、summary/daily/top、retention 删除。
- 验收：`ctest` 全绿；gcov 抽查新增代码核心分支。

## 6. 非目标（二期）

- SSE（`/api/events`）、Bearer 鉴权、前端独立构建管线、V2 密码加密。
