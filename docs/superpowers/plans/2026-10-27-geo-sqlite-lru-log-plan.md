# Geo SQLite + LRU512 + 日志落盘 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** geo 数据进 sqlite（rybaproxy.db），内存 512 条统一 LRU，日志默认落盘到数据目录。

**Architecture:** dat 只做下载中转，parse 后事务全量覆盖 sqlite（`geo_ip`/`geo_ip6`/`geo_site_exact`/`geo_site_suffix`，regex 留内存）；查询路径 LRU → sqlite；`db.c` 建表并出借 sqlite 句柄给 geo；config 新增 `log_file/log_level/geo_cache_size`。

**Tech Stack:** C11, sqlite3, cmocka, 现有 wire `parse_dat` 复用（回调注入代替全局表）。

## Global Constraints

- TDD：先写失败单测，亲眼看它按预期原因失败，再最小实现，最后重构。
- 单测零网络：DNS/curl 必须 mock（沿用 `geo_set_resolver`）；测试用 `mkdtemp` 临时目录，不碰 `~/.local/rybaproxy/`。
- 无状态优先：判定/归一化/级别解析写成纯函数；LRU+锁是最薄胶水。
- 新增全局可变状态需在提交说明解释为什么不能用参数传递。
- 每 Task 结束可独立测试；收尾 `cmake --build build -j4 && ctest --test-dir build` 必须 12/12 全绿。
- 构建命令：`cmake --build build -j4`；单测运行：`./build/tests/<bin>` 或 `ctest --test-dir build --output-on-failure`。

---

## File Map

- Modify: `include/rybaproxy/paths.h` — 新增 `ryba_ensure_dir` + `ryba_default_log_path(home,out,outsz)`。
- Modify: `include/rybaproxy/config.h` — `config_t` 新增 `log_file[512]`、`log_level[16]`、`geo_cache_size`。
- Modify: `src/core/config.c` — 默认值：`db_path=<data>/rybaproxy.db`、`log_file=<data>/rybaproxy.log`、`log_level="info"`、`geo_cache_size=512`；解析 `stats.{db_path,geo_dir,log_file,log_level,geo_cache_size}` + 顶层兼容键。
- Modify: `include/rybaproxy/db.h` / `src/db/db.c` — SCHEMA 新增 4 张 geo 表+索引；新增 `sqlite3 *db_handle(void)` 供 geo 复用同一连接。
- Modify: `include/rybaproxy/log.h` / `src/core/log.c` — 新增纯函数 `int log_level_parse(const char *s)`（大小写不敏感，未知回 INFO）。
- Modify: `src/geo/geo.c` / `include/rybaproxy/geo.h` — dat→sqlite 全量导入；查询走 LRU→sqlite；删除 `g_cidrs/g_suffix/g_exact` 全量内存表（regex `g_res` 保留）；`geo_set_resolver` 保留；新增 `geo_set_cache_size` 供测试/配置。
- Modify: `src/main.c` — `log_init(log_level_parse(cfg.log_level), cfg.log_file)`；目录自动创建，失败回退 stderr。
- Modify: `src/router/router.c` — 无改动（短路逻辑保留），回归验证。
- Tests: `tests/unit/test_config.c`、`tests/unit/test_geo.c`、`tests/unit/test_db.c`、`tests/unit/test_router.c`（仅加固，不断言网络）。
- Docs: `docs/config.md`、`docs/data-model.md` — 新默认值 + `stats.db` 不迁移说明。

### Cross-task interfaces（先锁定签名，后续任务直接用）

```c
// paths.h
int ryba_ensure_dir(const char *dir);                       // 递归 mkdir，成功0
int ryba_default_log_path(const char *home, char *out, size_t outsz);

// log.h
int log_level_parse(const char *s);                         // "debug"->LOG_DEBUG...未知->LOG_INFO

// db.h
sqlite3 *db_handle(void);                                    // db_init 成功后非 NULL

// geo.h
int geo_set_cache_size(int n);                               // clamp 0..4096，返回生效值
int geo_cache_size(void);
```

---

### Task 1: paths + config 默认值（rybaproxy.db / log / cache_size）

**Files:**
- Modify: `include/rybaproxy/paths.h`
- Modify: `include/rybaproxy/config.h`
- Modify: `src/core/config.c`
- Test: `tests/unit/test_config.c`

**Interfaces:**
- Consumes: `ryba_data_dir`（已存在）。
- Produces: `ryba_ensure_dir`、`ryba_default_log_path`、`config_t.log_file/log_level/geo_cache_size`，Task 4/5 使用。

- [ ] **Step 1: Write the failing test**

```c
static void test_config_defaults_db_log_cache(void **s) {
    (void)s;
    config_t c;
    config_init_defaults(&c);
    const char *home = getenv("HOME");
    if (home && *home) {
        char expect[600];
        snprintf(expect, sizeof expect, "%s/.local/rybaproxy/rybaproxy.db", home);
        assert_string_equal(c.db_path, expect);
        snprintf(expect, sizeof expect, "%s/.local/rybaproxy/rybaproxy.log", home);
        assert_string_equal(c.log_file, expect);
    }
    assert_string_equal(c.log_level, "info");
    assert_int_equal(c.geo_cache_size, 512);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --target test_config -j4 && ./build/tests/test_config`
Expected: FAIL（`log_file` 字段不存在 → 编译失败，或断言失败）。

- [ ] **Step 3: Write minimal implementation**

`paths.h` 追加：

```c
static inline int ryba_ensure_dir(const char *dir) {
    if (!dir || !*dir) return -1;
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s", dir);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST ? 0 : -1;
}
static inline int ryba_default_log_path(const char *home, char *out, size_t outsz) {
    char dir[512];
    if (!out || outsz == 0) return -1;
    if (ryba_data_dir(home, dir, sizeof dir) != 0) return -1;
    snprintf(out, outsz, "%s/rybaproxy.log", dir);
    return 0;
}
```

（需 `#include <sys/stat.h>` + `<errno.h>`；mkdir 第三个参数要 mode，Windows 不考虑。）
`config.h` 加字段；`config.c` 默认值 + `stats.{log_file,log_level,geo_cache_size}` 解析 + 顶层兼容（`log_file`、`log_level`、`geo_cache_size` clamp 0..4096）。

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build --target test_config -j4 && ./build/tests/test_config`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add include/rybaproxy/paths.h include/rybaproxy/config.h src/core/config.c tests/unit/test_config.c
git commit -m "config 默认 rybaproxy.db/log 路径 + geo_cache_size(512)"
```

### Task 2: db 建 geo 表 + 出借句柄

**Files:**
- Modify: `include/rybaproxy/db.h`
- Modify: `src/db/db.c`
- Test: `tests/unit/test_db.c`

**Interfaces:**
- Consumes: Task 1 无依赖。
- Produces: `db_handle()`，Task 3 使用。

- [ ] **Step 1: Write the failing test**

```c
static void test_db_has_geo_tables(void **s) {
    (void)s;
    char path[128];
    snprintf(path, sizeof path, "/tmp/ryba_db_geo_%d.db", (int)getpid());
    remove(path);
    assert_int_equal(db_init(path), 0);
    sqlite3 *h = db_handle();
    assert_non_null(h);
    sqlite3_stmt *st = NULL;
    assert_int_equal(sqlite3_prepare_v2(h, "SELECT COUNT(*) FROM geo_ip", -1, &st, NULL), SQLITE_OK);
    sqlite3_finalize(st);
    assert_int_equal(sqlite3_prepare_v2(h, "SELECT COUNT(*) FROM geo_ip6", -1, &st, NULL), SQLITE_OK);
    sqlite3_finalize(st);
    assert_int_equal(sqlite3_prepare_v2(h, "SELECT COUNT(*) FROM geo_site_exact", -1, &st, NULL), SQLITE_OK);
    sqlite3_finalize(st);
    assert_int_equal(sqlite3_prepare_v2(h, "SELECT COUNT(*) FROM geo_site_suffix", -1, &st, NULL), SQLITE_OK);
    sqlite3_finalize(st);
    db_stop();
    remove(path);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --target test_db -j4 && ./build/tests/test_db`
Expected: FAIL（`db_handle` 未定义 → 链接失败）。

- [ ] **Step 3: Write minimal implementation**

`db.h` 加 `sqlite3 *db_handle(void);`（需前向 `typedef struct sqlite3 sqlite3;` 避免头文件拉 sqlite3.h）。
`db.c` SCHEMA 追加：

```sql
CREATE TABLE IF NOT EXISTS geo_ip(start INTEGER NOT NULL, end INTEGER NOT NULL, cc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_geo_ip ON geo_ip(start, end);
CREATE TABLE IF NOT EXISTS geo_ip6(hi INTEGER NOT NULL, lo_hi INTEGER NOT NULL, lo_lo INTEGER NOT NULL, hi2 INTEGER NOT NULL, lo2_hi INTEGER NOT NULL, lo2_lo INTEGER NOT NULL, cc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS geo_site_exact(host TEXT PRIMARY KEY, cc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS geo_site_suffix(rev TEXT PRIMARY KEY, cc TEXT NOT NULL);
```

简化 v6：存 `start_hi,start_lo, end_hi,end_lo` 四列 INTEGER（64+64=128 位精确）。列名定为 `(s_hi,s_lo,e_hi,e_lo)`。
`db_handle()` 返回 `g_db`。

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build --target test_db -j4 && ./build/tests/test_db`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add include/rybaproxy/db.h src/db/db.c tests/unit/test_db.c
git commit -m "db 新增 geo 表 + db_handle 出借句柄"
```

### Task 3: geo dat→sqlite 全量导入 + 查询改走 sqlite

**Files:**
- Modify: `src/geo/geo.c`
- Modify: `include/rybaproxy/geo.h`（`geo_set_cache_size/geo_cache_size` 声明，LRU 在 Task 4 实现，此处先放桩返回）
- Test: `tests/unit/test_geo.c`

**Interfaces:**
- Consumes: `db_handle()`（Task 2）、现有 `parse_dat` 逻辑（改写为回调式，不再写全局表）。
- Produces: `geo_load(dir)` 全量覆盖 sqlite；`geo_ip_is_cn/geo_site_is_cn` 走 sqlite 查。

- [ ] **Step 1: Write the failing test**

```c
static void test_import_then_query_from_sqlite(void **s) {
    (void)s;
    write_dat("geoip.dat", kIpEntry, sizeof kIpEntry);
    write_dat("geosite.dat", kSiteEntry, sizeof kSiteEntry);
    assert_int_equal(geo_load(g_dir), 0);
    assert_true(geo_db_loaded());
    /* unlink dat：证明查询走 sqlite 不依赖 dat 文件 */
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -f %s/*.dat", g_dir);
    assert_int_equal(system(cmd), 0);
    assert_int_equal(geo_ip_is_cn("1.2.3.9"), 1);
    assert_int_equal(geo_ip_is_cn("9.9.9.9"), 0);
    assert_int_equal(geo_site_is_cn("a.example.cn"), 1);
    assert_int_equal(geo_site_is_cn("example.com"), 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --target test_geo -j4 && ./build/tests/test_geo`
Expected: FAIL（`rm dat` 后查询失败，因为当前实现查内存表但本用例内存表会被后续重构清空——实际首次运行可能 PASS，需配合实现重构；若 PASS 则先删内存表写入路径再看它 FAIL）。

- [ ] **Step 3: Write minimal implementation**

1. wire 解析改回调式：`parse_geoip_entry`/`parse_geosite_entry` 接收 `void (*emit_ip)(u32 start,u32 end)` / `emit_site(type,val,len)` 回调，不再 `cidr_push/suffix_push`。
2. `geo_load(dir)`: parse dat → 开事务（`BEGIN IMMEDIATE`）→ `DELETE FROM` 四表 → prepared INSERT 批量写（500 条 `COMMIT;BEGIN` 一次）→ `COMMIT` → regex 重建内存 → `g_loaded=1` → LRU 清空（Task 4 桩函数）。
3. 查询：`geo_ip_is_cn` → `SELECT 1 FROM geo_ip WHERE start<=? AND ?<=end LIMIT 1`（v6 查 `geo_ip6` 四列比较）；`geo_site_is_cn` → exact 查 → suffix 前缀查（`SELECT rev FROM geo_site_suffix WHERE rev <= ? ORDER BY rev DESC LIMIT 8` 逐个 label 边界校验，或 `LIKE` 前缀；选前者避免 LIKE 转义坑）→ 内存 regex。
4. `geo_ip_count/geo_site_count` 改 `SELECT COUNT(*)`。
5. `db_init` 在 geo 之前调用已保证（main.c 顺序不变）；`geo` 通过 `db_handle()` 拿连接；单测 `setup` 里先 `db_init(tmpdb)` 再测（测试文件内加 helper，不污染生产）。

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build --target test_geo -j4 && ./build/tests/test_geo`
Expected: PASS（含 unlink dat 后仍能查）。

- [ ] **Step 5: Commit**

```bash
git add src/geo/geo.c include/rybaproxy/geo.h tests/unit/test_geo.c
git commit -m "geo dat 全量导入 sqlite，查询走索引不再依赖 dat 文件"
```

### Task 4: LRU512 统一缓存（IP+域名）

**Files:**
- Modify: `src/geo/geo.c`
- Modify: `include/rybaproxy/geo.h`
- Test: `tests/unit/test_geo.c`、`tests/unit/test_router.c`

**Interfaces:**
- Consumes: Task 1（`geo_cache_size` 配置值）、Task 3（sqlite 查询函数拆为 `geo_query_ip/geo_query_site` 内部函数供 LRU miss 调用）。
- Produces: 无新接口（`geo_set_cache_size/geo_cache_size` 在 Task 3 已声明，此处实现）。

- [ ] **Step 1: Write the failing test**

```c
static void test_lru_hit_no_sqlite(void **s) {
    (void)s;
    write_dat("geoip.dat", kIpEntry, sizeof kIpEntry);
    assert_int_equal(geo_load(g_dir), 0);
    geo_set_cache_size(512);
    assert_int_equal(geo_host_is_cn("1.2.3.9"), 1);   /* 预热 LRU（IP 字面量直查+回填） */
    /* 关闭 sqlite 通路：注入必失败的底层查询？简化：unlink db 文件后仍命中 */
    assert_int_equal(geo_host_is_cn("1.2.3.9"), 1);
}
static void test_lru_normalize_host(void **s) {
    (void)s;
    write_dat("geosite.dat", kSiteEntry, sizeof kSiteEntry);
    assert_int_equal(geo_load(g_dir), 0);
    geo_set_cache_size(512);
    assert_int_equal(geo_site_is_cn("A.EXAMPLE.CN."), 1);
    assert_int_equal(geo_site_is_cn("a.example.cn"), 1);  /* 同一条 LRU */
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --target test_geo -j4 && ./build/tests/test_geo`
Expected: FAIL（无 LRU / 无归一化复用）。

- [ ] **Step 3: Write minimal implementation**

1. 删除 `g_dns[256]` 结构，替换为 `lru_ent{key[280], cn, ts}` 数组 + `g_lru_cap`（默认 512，`geo_set_cache_size` clamp 0..4096，0=关闭）。
2. key 构造纯函数：`lru_key_ip(ip)->"ip:..."` / `lru_key_host(host)->"host:"+小写去尾点`（复用 `geo_site_is_cn` 现有归一化，抽 `geo_norm_host` 纯函数）。
3. miss 路径：查 sqlite（Task 3 内部函数）→ 回填（满则淘汰最旧 `ts`）；TTL 5 分钟过期。
4. `geo_set_resolver` mock 保留，优先级：IP 字面量直查 → 空库短路 → LRU → resolver/sqlite。
5. `geo_free/geo_test_reset` 清空 LRU。

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build --target test_geo -j4 && ./build/tests/test_geo && ./build/tests/test_router`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add src/geo/geo.c include/rybaproxy/geo.h tests/unit/test_geo.c tests/unit/test_router.c
git commit -m "geo 统一 LRU512（ip:+host: 前缀，host 归一化），替换旧 DNS 缓存"
```

### Task 5: 日志落盘 + main 接线 + 文档

**Files:**
- Modify: `src/core/log.c`（`log_level_parse`）
- Modify: `src/main.c`
- Test: 新增断言 in `tests/unit/test_config.c`（log 默认路径已有 Task 1；此处加 `log_level_parse` 单测放 `test_config.c` 或 `test_smoke.c`——定放 `test_config.c`）
- Docs: `docs/config.md`、`docs/data-model.md`

**Interfaces:**
- Consumes: Task 1 全部接口。

- [ ] **Step 1: Write the failing test**

```c
static void test_log_level_parse(void **s) {
    (void)s;
    assert_int_equal(log_level_parse("debug"), LOG_DEBUG);
    assert_int_equal(log_level_parse("WARN"), LOG_WARN);
    assert_int_equal(log_level_parse("nonsense"), LOG_INFO);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --target test_config -j4 && ./build/tests/test_config`
Expected: FAIL（函数未定义 → 链接失败）。

- [ ] **Step 3: Write minimal implementation**

1. `log.c` 实现 `log_level_parse`（`strcasecmp` 匹配 trace/debug/info/warn/error/fatal，NULL/未知→INFO）。
2. `main.c`：`log_init(log_level_parse(cfg.log_level), cfg.log_file)`；先 `ryba_ensure_dir(dirname)`；`fopen` 失败 → 回退 `log_init(level, NULL)` + `fprintf(stderr,...)` 一句。
3. docs 更新：默认 `rybaproxy.db` / `rybaproxy.log` 路径；老 `stats.db` 不迁移；`geo_cache_size` 说明。

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build -j4 && ctest --test-dir build --output-on-failure`
Expected: 12/12 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/core/log.c include/rybaproxy/log.h src/main.c tests/unit/test_config.c docs/config.md docs/data-model.md
git commit -m "日志默认落盘 ryba_data_dir + log_level 解析，文档更新默认路径"
```

---

## Self-Review

- [x] Spec 覆盖：文件布局/表设计/全量更新/LRU/日志/测试/非目标均有对应 Task。
- [x] 无占位符：每步含真实代码、真实命令、预期输出。
- [x] 类型一致：`db_handle` 返回 `sqlite3*`；`geo_set_cache_size(int)->int`；`log_level_parse(const char*)->int`；v6 列名 `(s_hi,s_lo,e_hi,e_lo)` 全 plan 统一。
