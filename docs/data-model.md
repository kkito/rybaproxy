# 数据模型与统计

## 1. 存储

- SQLite 3（WAL 模式），文件默认 `~/.local/rybaproxy/stats.db`（可配置 `stats.db_path` / `geo_dir` 指定目录，dat 落 `geo_dir`）；systemd 部署可显式配到 /var/lib
- 写入线程单连接，批量事务；读（Web）使用只读连接或 WAL 读

## 2. 表结构

### 2.1 schema_version

```sql
CREATE TABLE schema_version (version INTEGER NOT NULL);
```

### 2.2 upstream_profiles

```sql
CREATE TABLE upstream_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,            -- direct|http|socks5
  host TEXT,
  port INTEGER,
  username TEXT,
  password TEXT,                 -- 明文存储 v1（v2 加密）
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
```

### 2.3 rules

```sql
CREATE TABLE rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  priority INTEGER NOT NULL DEFAULT 100,
  enabled INTEGER NOT NULL DEFAULT 1,
  domain_pattern TEXT,
  ip_cidr TEXT,
  port INTEGER DEFAULT 0,
  protocol TEXT DEFAULT 'any',
  upstream_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(upstream_id) REFERENCES upstream_profiles(id)
);
```

### 2.4 sessions（明细，保留 3 个月）

```sql
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  protocol TEXT NOT NULL,        -- http|socks5
  client_ip TEXT NOT NULL,
  target_host TEXT NOT NULL,
  target_port INTEGER NOT NULL,
  method TEXT,                   -- GET/CONNECT/SOCKS5-CONNECT
  upstream_id INTEGER,
  upstream_name TEXT,
  status INTEGER NOT NULL,       -- 0=ok 1=error 2=timeout
  error_code INTEGER,
  error_msg TEXT,
  bytes_up INTEGER NOT NULL,
  bytes_down INTEGER NOT NULL,
  started_at INTEGER NOT NULL,   -- unix ms
  ended_at INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  nginx_forwarded INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_sessions_started ON sessions(started_at);
CREATE INDEX idx_sessions_client ON sessions(client_ip, started_at);
CREATE INDEX idx_sessions_target ON sessions(target_host, started_at);
CREATE INDEX idx_sessions_upstream ON sessions(upstream_id, started_at);
```

### 2.5 http_requests（可选，普通 HTTP 请求级明细）

```sql
CREATE TABLE http_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER,
  method TEXT NOT NULL,
  url TEXT,
  host TEXT,
  status_code INTEGER,
  bytes_up INTEGER,
  bytes_down INTEGER,
  started_at INTEGER NOT NULL,
  duration_ms INTEGER,
  FOREIGN KEY(session_id) REFERENCES sessions(id)
);
```

v1 默认开启请求级记录（可配置 `record_http_requests`），CONNECT 隧道不产生多条。

### 2.6 aggregates_daily（长期保留）

```sql
CREATE TABLE aggregates_daily (
  day TEXT NOT NULL,             -- YYYY-MM-DD
  upstream_id INTEGER,
  client_ip TEXT,                -- NULL 表示全局
  target_host TEXT,              -- NULL 表示全局
  sessions INTEGER NOT NULL,
  bytes_up INTEGER NOT NULL,
  bytes_down INTEGER NOT NULL,
  errors INTEGER NOT NULL,
  PRIMARY KEY (day, upstream_id, client_ip, target_host)
);
```

每天 00:05 由写入线程汇总前一天；aggregates 保留 1 年（可配置），明细 3 个月。

### 2.7 settings

```sql
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
```

## 3. 保留策略

- 启动时 + 每天 03:00 执行：
  - `DELETE FROM sessions WHERE started_at < (now - 90 days)`
  - `DELETE FROM http_requests WHERE started_at < (now - 90 days)`
  - `DELETE FROM aggregates_daily WHERE day < (now - 365 days)`（可配置）
- 删除后 `VACUUM` 每周一次（或 `PRAGMA incremental_vacuum`）

## 4. 统计维度（Web 展示）

- 总览：QPS/吞吐、活跃连接、总流量、错误率
- 按时间：1m/5m/1h/1d 曲线（基于 sessions 聚合查询）
- 按上游：连接数、流量、错误率、延迟分布
- 按客户端 IP：Top N
- 按目标 host：Top N
- 按状态码（HTTP）

## 5. 写入路径

```
数据面 session 结束
  -> 构造 stats_event_t
  -> 入队 (有界队列 65536)
写入线程:
  -> 批量取 (最多 256)
  -> BEGIN; INSERT...; COMMIT
  -> 更新内存计数器（供 Web 实时读）
```

队列满：丢弃事件，`dropped_events++`，日志告警。

## 6. 实时计数器（内存）

- `active_connections`
- `total_sessions`, `total_bytes_up/down`（原子 uint64）
- `per_upstream` 计数
- Web 读取时加锁或使用原子；刷新间隔 1s
