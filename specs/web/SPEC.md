---
id: ryba-web
type: module-design
status: active
title: Web 管理面板
parent: ryba-architecture
---

## Responsibility

管理 HTTP 服务与 REST API：上游/规则 CRUD、geo 状态下载与检测、会话与统计查询、设置、内存日志查看；前端为无构建单页（5s 轮询）。

## Boundary

- Owns: `src/web/web.c`（路由分发）、`src/web/web_api.c`、`src/web/web_page.h`（内联前端）。
- May use: ryba-persist（只读查询 + 规则/上游双写）、server_ctx 内存态（持 lock 双写）。
- Never: 直连数据面 session 结构；实时指标走内存计数器与 DB 聚合两条路。

## Decisions

- 统一信封 `{ok:true,data}` / `{ok:false,error:{code,message}}`；分页 `{data,total,limit,offset}`；bad json→400、无 id→404、DB 失败→500。
- `GET /api/stats` 保留兼容，`GET /api/metrics` 同义；`GET /healthz` 无鉴权。
- B 档范围：不做 SSE（轮询代替）、不做 Bearer 鉴权；CSS 不动只改 JS。
