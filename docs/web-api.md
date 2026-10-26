# Web 界面与 REST API

## 1. 服务

- 管理 HTTP 服务监听 `web.listen`（默认 `127.0.0.1:9090`）
- 提供静态页面（HTML/CSS/JS 嵌入二进制）与 JSON API
- 前端为单页应用（无构建依赖，原生 JS + fetch）

## 2. 页面

- `/` Dashboard：实时指标、趋势图
- `/connections` 活跃连接列表（WebSocket 或轮询）
- `/rules` 规则管理
- `/upstreams` 上游档案管理
- `/stats` 统计查询（时间范围、维度）
- `/logs` 最近日志
- `/settings` 配置

## 3. REST API（v1）

鉴权：`Authorization: Bearer <token>`（除 `/healthz`）

### 3.1 健康

- `GET /healthz` -> `{ "status": "ok", "version": "..." }`

### 3.2 指标

- `GET /api/metrics` -> 实时计数器 + 近 1m/5m 聚合

### 3.3 上游

- `GET /api/upstreams`
- `POST /api/upstreams`
- `PUT /api/upstreams/:id`
- `DELETE /api/upstreams/:id`
- `POST /api/upstreams/:id/test`（连通性测试）

### 3.4 规则

- `GET /api/rules`
- `POST /api/rules`
- `PUT /api/rules/:id`
- `DELETE /api/rules/:id`
- `POST /api/rules/reload`

### 3.5 会话/统计

- `GET /api/sessions?from=&to=&client=&target=&upstream=&limit=&offset=`
- `GET /api/sessions/:id`
- `GET /api/stats/summary?from=&to=&group_by=upstream|client|target|day`
- `GET /api/stats/timeseries?from=&to=&bucket=1m|5m|1h|1d&metric=bytes|sessions|errors`
- `GET /api/stats/top?by=client|target&limit=20&from=&to=`

### 3.6 设置

- `GET /api/settings`
- `PUT /api/settings`

### 3.7 日志

- `GET /api/logs?level=&limit=`

## 4. 实时推送

- `GET /api/events`（Server-Sent Events）推送：新会话、会话结束、指标快照（每 1s）

## 5. 响应格式

```json
{ "ok": true, "data": { ... } }
{ "ok": false, "error": { "code": "NOT_FOUND", "message": "..." } }
```

分页：`{ "data": [...], "total": 123, "limit": 50, "offset": 0 }`

## 6. 静态资源嵌入

使用脚本将 `web/static/*` 转为 C 字节数组编译进二进制，避免运行时依赖文件路径。开发模式可从 `--web-root` 读取文件。
