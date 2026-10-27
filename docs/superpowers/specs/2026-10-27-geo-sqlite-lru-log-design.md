# Geo SQLite + LRU + 日志落盘 设计文档

**Goal:** geo 数据进 sqlite（rybaproxy.db），内存 512 条统一 LRU，日志默认落盘。

**Architecture:** dat 只做下载中转，解析后全量覆盖 sqlite 表；查询走 LRU(512) → sqlite；regex 小表留内存。db 改名不迁移。

**Tech Stack:** C11, sqlite3（已依赖）, cmocka, wire dat 解析复用现有 parse_dat。

## Global Constraints

- TDD：先失败单测，亲眼看它按预期失败，再最小实现。
- 单测零网络：DNS/curl 走 mock 注入；测试用临时目录，不碰 `~/.local/rybaproxy/`。
- 无状态优先：判定逻辑纯函数化；LRU/锁是最薄胶水。
- 收尾：`cmake --build build -j4 && ctest --test-dir build` 12/12 全绿。

---

## 1. 文件布局

- 默认数据目录：`~/.local/rybaproxy/`（`ryba_data_dir`，不变）。
- `rybaproxy.db`：stats 旧表 + 新增 geo 表。配置键 `stats.db_path` 语义不变，默认值改为 `<数据目录>/rybaproxy.db`。
- 老 `stats.db` 不迁移（B）：启动不 rename、不兼容读；老数据用户手动处理。docs 注明。
- `rybaproxy.log`：默认 `<数据目录>/rybaproxy.log`；可配 `stats.log_file`（顶层 `log_file` 兼容）+ `stats.log_level`（顶层 `log_level` 兼容，默认 `info`）。
- `geo_dir` 不变：dat 下载中转目录；dat 文件下载后保留（方便排查）。
- 测试：`mkdtemp` 临时目录 + `RYBA_GEO_DIR` 注入。

## 2. sqlite 表设计（Task 1）

```sql
CREATE TABLE IF NOT EXISTS geo_ip(start INTEGER NOT NULL, end INTEGER NOT NULL, cc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_geo_ip ON geo_ip(start, end);
CREATE TABLE IF NOT EXISTS geo_site_exact(host TEXT PRIMARY KEY, cc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS geo_site_suffix(rev TEXT PRIMARY KEY, cc TEXT NOT NULL); -- 反转小写后缀
```

- IPv4 存 32 位整数（`::ffff:a.b.c.d` 映射后只用低 32 位比较？否——v6 用 128 位存 BLOB 另表，或统一存 text 整数？**定：v4 转 uint32 存 INTEGER；v6 转两 INTEGER(high,low) 存 `geo_ip6` 表**，避免精度丢失）。
- `cc` 目前只有 `CN` 行（dat 里非 CN 条目不入库？**定：只入库 `cc='CN'` 条目**，查无即非 CN/未知由 loaded 语义决定，保持现有三值语义）。
- regex 条目（几十条）不进 sqlite，仍放内存小表 `g_res`，随 `geo_load` 重建。
- 计数接口 `geo_ip_count/geo_site_count` 改为 `SELECT COUNT(*)`。

## 3. 全量更新流程（Task 2）

- `geo_download(dir)`：curl 下两个 dat（逻辑不变）→ `geo_import(dir)` 新函数：parse wire → 开事务 → `DELETE FROM geo_ip/...` → 批量 INSERT（prepared statement 复用，500 条一 commit 子批次防 WAL 膨胀）→ `COMMIT` → 内存 regex 重建 + `g_loaded=1` + LRU 清空。
- `geo_load(dir)` 语义改为 `geo_import(dir)`（同目录 dat → sqlite 全量覆盖）；保留函数名避免调用方改动。
- `db_init` 建表（新增 3 表 + 索引）；启动：若 sqlite geo 表非空 → `g_loaded=1` 直接用（不 parse dat）；为空但 dat 存在 → 导入一次；都无 → 空库未知语义。
- 失败原子性：事务 ROLLBACK，旧数据保留，`g_loaded` 不变，返回 -1。

## 4. LRU 512（Task 3）

- 统一表：key 前缀区分 `ip:` / `host:`；host 入口前归一化（小写+去尾点，复用 `geo_site_is_cn` 现有逻辑抽纯函数）。
- 默认 512；`stats.geo_cache_size` 可配（0=关闭，直查 sqlite；上限 4096，越界 clamp）。
- 替换旧 `g_dns[256]`：删除 DNS 缓存结构，LRU 存最终判定 `cn(1/0/-1)` + 时间戳（TTL 5 分钟保留）。
- 同一把 `g_lock`；`geo_free`/`geo_test_reset` 清空 LRU + `g_resolver=NULL`。
- miss 路径：LRU → sqlite（IP：`SELECT 1 FROM geo_ip WHERE start<=? AND ?<=end LIMIT 1`；域名：exact → suffix（`rev LIKE reversed%` 前缀查 + label 边界校验）→ 内存 regex）→ 回填 LRU。
- 空库短路保留：`!loaded → -1`，不查 sqlite/LRU（除私网 IP 直接 1）。
- `geo_set_resolver` mock 机制保留：sqlite 有数据时注入 resolver 仍走注入路径（单测零网络）。

## 5. 日志落盘（Task 4）

- `config_t` 新增 `log_file[512]`、`log_level[16]`；默认 `log_file=<数据目录>/rybaproxy.log`，`log_level=info`。
- `main.c`：`log_init(level, file)` 传文件路径；父目录不存在自动创建（复用 `geo_ensure_dir` 思想抽 `ryba_ensure_dir` 进 `paths.h`）；打开失败回退 stderr + 一句 stderr 告警，不崩。
- 日志级别字符串解析纯函数 `log_level_parse`（大小写不敏感，未知回 INFO），可单测。
- 暂不做轮转。

## 6. 测试计划

- `test_geo`：导入后 `SELECT COUNT` 对得上；全量二次导入不翻倍；sqlite 有数据重启（re-open）直接 loaded；LRU 命中不碰 sqlite（注入计数 stub / 或 unlink sqlite 文件后仍命中）；`geo_cache_size=0` 直查；归一化 `QQ.COM.`==`qq.com` 同一条。
- `test_router`：哨兵 resolver 保留；新增 LRU 命中路径不断言网络。
- `test_config`：默认 `rybaproxy.db` + 默认 log 路径；`geo_cache_size` 解析与 clamp。
- `test_web_page`：已有 geo 单测保持。
- 单测 sqlite 用 `:memory:` 或 `mkdtemp` 文件，不碰家目录。

## 7. 非目标

- log 轮转、geo 增量更新、v6 全量优化（按现有量级够用）、stats.db 自动迁移。
