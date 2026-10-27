# Geo 分流 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 规则支持 geoip:cn / geosite:cn / 取反条件，IP 库界面手动下载，新增检测页验证分流。

**Architecture:** 新建 `src/geo/` 模块（dat 解析 + 内存查询 + DNS 缓存），`router.c` 的 `rule_matches` 消费查询接口，`web_api.c` 加三个 `/api/geo/*` 端点，`web_page.h` 加管理卡与检测页。dat 文件不进源码，落盘在 db 同目录。

**Tech Stack:** C11, SQLite（规则两字段持久化）, CivetWeb（API）, cmocka（单测）, 无新第三方依赖。

## Global Constraints

- CSS 不动只改 JS（`src/web/web_page.h` 内联）。
- 信封统一 `{ok:true,data}` / `{ok:false,error:{code,message}}`。
- 无前端构建；YAGNI（仅 cn/!cn，纯手动下载，无定时任务）。
- dat 文件不进项目源码；界面按钮下载。
- `ctest` 全过才可提交。

---

### Task 1: geo 模块骨架 + IP 查询（含私网视同 cn）

**Files:**
- Create: `include/rybaproxy/geo.h`
- Create: `src/geo/geo.c`
- Test: `tests/unit/test_geo.c`（新建，`tests/CMakeLists.txt` 加 `add_ryba_test(test_geo unit/test_geo.c)`）

**Interfaces:**
- Consumes: 无（独立模块，IPv4/IPv6 解析自实现）。
- Produces: `int geo_init(void)` / `void geo_free(void)`；`int geo_ip_is_cn(const char *ip)`（1=是CN/私网，0=否，-1=无效输入）；`int geo_db_loaded(void)`；Task 2/3/4 依赖这三个符号。

- [ ] **Step 1: 写头文件 `include/rybaproxy/geo.h`**

```c
#ifndef RYBAPROXY_GEO_H
#define RYBAPROXY_GEO_H
/* Geo 分流：IP 段查询 + 域名清单查询。数据来自开源社区 geoip.dat/geosite.dat。 */
int geo_init(void);
void geo_free(void);
int geo_db_loaded(void); /* 1=至少一个 dat 已加载 */
/* 返回 1=CN(含私网) 0=非CN未知外 -1=输入无效 */
int geo_ip_is_cn(const char *ip);
#endif
```

- [ ] **Step 2: 写 failing 单测 `tests/unit/test_geo.c`（仅 IP 部分，dat 加载留空实现也能跑）**

```c
#include <cmocka.h>
#include <assert.h>
#include "rybaproxy/geo.h"
static void test_private_is_cn(void **s) {
    (void)s;
    assert_int_equal(geo_ip_is_cn("192.168.1.1"), 1);
    assert_int_equal(geo_ip_is_cn("10.0.0.5"), 1);
    assert_int_equal(geo_ip_is_cn("127.0.0.1"), 1);
    assert_int_equal(geo_ip_is_cn("::1"), 1);
}
static void test_invalid_input(void **s) {
    (void)s;
    assert_int_equal(geo_ip_is_cn(NULL), -1);
    assert_int_equal(geo_ip_is_cn("not-an-ip"), -1);
}
static void test_db_unloaded(void **s) {
    (void)s;
    geo_init();
    assert_int_equal(geo_db_loaded(), 0);
    geo_free();
}
int main(void) {
    const struct CMUnitTest t[] = {
        cmocka_unit_test(test_private_is_cn),
        cmocka_unit_test(test_invalid_input),
        cmocka_unit_test(test_db_unloaded),
    };
    return cmocka_run_group_tests(t, NULL, NULL);
}
```

- [ ] **Step 3: 运行确认失败**

Run: `cmake --build build -j4 && ctest --test-dir build -R test_geo -V`
Expected: FAIL（`geo.c` 不存在导致链接失败）

- [ ] **Step 4: 最小实现 `src/geo/geo.c`**

```c
#include "rybaproxy/geo.h"
#include <arpa/inet.h>
#include <string.h>
static int g_loaded = 0;
int geo_init(void) { g_loaded = 0; return 0; }
void geo_free(void) { g_loaded = 0; }
int geo_db_loaded(void) { return g_loaded; }
/* 私网段视同 CN；其余需 dat，未加载返回 0（未知按非CN） */
int geo_ip_is_cn(const char *ip) {
    if (!ip || !*ip) return -1;
    struct in6_addr a6;
    struct in_addr a4;
    if (inet_pton(AF_INET, ip, &a4) == 1) {
        unsigned int h = ntohl(a4.s_addr);
        if ((h >> 24) == 10) return 1;
        if ((h >> 20) == (172 << 4 | 1)) { unsigned b = (h >> 16) & 0xFF; if (b >= 16 && b <= 31) return 1; }
        if ((h >> 16) == (192 << 8 | 168)) return 1;
        if ((h >> 24) == 127) return 1;
        return 0; /* 无 dat：公网未知→非CN */
    }
    if (inet_pton(AF_INET6, ip, &a6) == 1) {
        static const unsigned char loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (memcmp(&a6, loop, 16) == 0) return 1;
        if (a6.s6_addr[0] == 0xFC || a6.s6_addr[0] == 0xFD) return 1; /* unique local */
        if (a6.s6_addr[0] == 0xFE && (a6.s6_addr[1] & 0xC0) == 0x80) return 1; /* link local */
        return 0;
    }
    return -1;
}
```

注意：`172.16/12` 判断用 `(h>>20)==0xAC1` 更直接，可用 `((h & 0xFFF00000) == 0xAC100000)`。

- [ ] **Step 5: 运行通过**

Run: `cmake --build build -j4 && ctest --test-dir build -R test_geo -V`
Expected: PASS（`src/*.c` 被 GLOB 自动收录进 `rybaproxy_core`，无需改顶层 CMake）

- [ ] **Step 6: Commit**

```bash
git add include/rybaproxy/geo.h src/geo/geo.c tests/unit/test_geo.c tests/CMakeLists.txt
git commit -m "feat(geo): module skeleton + private-IP-as-CN query"
```

---

### Task 2: dat 解析器 + 文件加载（geoip.dat / geosite.dat）

**Files:**
- Modify: `src/geo/geo.c`（追加解析与加载）
- Modify: `include/rybaproxy/geo.h`（追加 `geo_load(const char *dir)`、`geo_ip_count/geo_site_count`、`geo_site_is_cn`）
- Test: `tests/unit/test_geo.c`（追加迷你 dat 构造 + 解析断言）

**Interfaces:**
- Consumes: Task 1 的 `geo_init/geo_free/geo_ip_is_cn`。
- Produces: `int geo_load(const char *dir)`（读 `<dir>/geoip.dat` + `<dir>/geosite.dat`，成功返回 0，缺文件返回 -1 但不崩）；`int geo_site_is_cn(const char *host)`（1/0/-1 语义同 IP；IP 字面量直接 0）；`size_t geo_ip_count(void)` / `size_t geo_site_count(void)`（供 `/api/geo/status`）。

dat 二进制格式（写入 plan 备查，实现时照此解析）：

```
GeoIP.dat  := varint(count) { varint(addr_len) addr_bytes varint(prefix) }...
  addr_bytes: IPv4=4字节 / IPv6=16字节大端；prefix: 0-32/0-128
GeoSite.dat := varint(count) { u8 type varint(len) bytes }...
  type: 0=exact("qq.com") 1=suffix("qq.com" 含自身与子域) 2=regex(PCRE 源串)
```

- [ ] **Step 1: 追加 failing 单测（内存构造迷你 dat → 落盘 → geo_load → 查询）**

```c
static void test_load_mini_dat(void **s) {
    (void)s;
    /* geoip: 1.2.3.0/24 ；geosite: suffix "example.cn" */
    unsigned char ipdat[] = {
        0x01,             /* count=1 */
        0x04, 1,2,3,0,    /* len=4 addr=1.2.3.0 */
        0x18,             /* prefix=24 */
    };
    unsigned char sitedat[] = {
        0x01,             /* count=1 */
        0x01, 0x0A,       /* type=1 suffix len=10 */
        'e','x','a','m','p','l','e','.','c','n',
    };
    char dir[] = "/tmp/ryba_geo_XXXXXX";
    assert_non_null(mkdtemp(dir));
    char p1[256], p2[256];
    snprintf(p1, sizeof p1, "%s/geoip.dat", dir);
    snprintf(p2, sizeof p2, "%s/geosite.dat", dir);
    FILE *f = fopen(p1, "wb"); fwrite(ipdat, 1, sizeof ipdat, f); fclose(f);
    f = fopen(p2, "wb"); fwrite(sitedat, 1, sizeof sitedat, f); fclose(f);
    geo_init();
    assert_int_equal(geo_load(dir), 0);
    assert_true(geo_db_loaded());
    assert_int_equal(geo_ip_is_cn("1.2.3.9"), 1);
    assert_int_equal(geo_ip_is_cn("9.9.9.9"), 0);
    assert_int_equal(geo_site_is_cn("a.example.cn"), 1);
    assert_int_equal(geo_site_is_cn("example.com"), 0);
    assert_true(geo_ip_count() == 1 && geo_site_count() == 1);
    geo_free();
}
```

同时在 `main` 的数组里注册 `cmocka_unit_test(test_load_mini_dat)`。

- [ ] **Step 2: 运行确认失败**

Run: `ctest --test-dir build -R test_geo -V`
Expected: FAIL（`geo_load`/`geo_site_is_cn` 未定义）

- [ ] **Step 3: 实现解析 + 加载（追加到 `src/geo/geo.c`）**

要点（完整代码由执行者写，约束如下）：
  - varint 解码：`read_varint(const unsigned char **pp, const unsigned char *end, uint64_t *out)`，溢出/`end` 越界返回 -1。
  - IP 表：`typedef struct { unsigned char addr[16]; int bits; int is6; } cidr_t;` 解析完按 `(is6, addr, bits)` 排序；查询时 IPv4 映射为 IPv4-mapped IPv6 统一比较，二分找最长前缀命中。CN 判定 = 命中 dat 中的 CN 条目（本 Task 的 dat 即 CN 集合，文件里有什么就是 CN）。
  - 域名表：suffix 存小写反转串，查询反转比较前缀；exact 用哈希/线性（条目测试规模小，生产可用 `hsearch` 或排序二分）；regex 用 `regcomp/regexec` 预编译，`geo_free` 时 `regfree`。
  - `geo_load(dir)`：两个文件任一缺失 → 返回 -1 且已解析部分保留（旧数据不清空，调用方决定；首次加载失败则 `loaded=0`）；解析错误 → -1。
  - 线程安全：`geo_load` 与查询并发时加模块内 `pthread_mutex_t`（读多写少，简单互斥即可）。
  - `geo_ip_is_cn` 升级：先走私网判断，再查 dat 表；dat 未加载 → 公网返回 0。

- [ ] **Step 4: 运行通过**

Run: `cmake --build build -j4 && ctest --test-dir build -R test_geo -V`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/geo/geo.c include/rybaproxy/geo.h tests/unit/test_geo.c
git commit -m "feat(geo): dat parser + dir loader with mini-dat tests"
```

---

### Task 3: 规则 `geo_ip / geo_site` 条件 + DNS 解析选路

**Files:**
- Modify: `include/rybaproxy/router.h`（`rule_t` 加 `char geo_ip[16]; char geo_site[16];`）
- Modify: `src/router/router.c`（`rule_matches` 加 geo 分支；`router_select` 签名不变）
- Modify: `src/geo/geo.c` + `include/rybaproxy/geo.h`（追加 `geo_host_is_cn(host, &via_dns)`：域名→DNS→IP→查段，5 分钟缓存；IP 字面量直查）
- Test: `tests/unit/test_router.c`（追加 geo 条件单测，用 Task 2 式迷你 dat 预置数据）

**Interfaces:**
- Consumes: Task 2 的 `geo_ip_is_cn/geo_site_is_cn`。
- Produces: `rule_matches` 新语义（Task 4 的 API/DB 照此透传）；`int geo_host_is_cn(const char *host)`（1=CN 0=非CN -1=未知/DNS失败）。

匹配语义（与 spec 一致，实现时逐条照抄）：

```c
if (rule->geo_ip[0]) {
    int cn = geo_host_is_cn(host); /* -1=未知 */
    if (!strcmp(rule->geo_ip, "cn") && cn != 1) return 0;
    if (!strcmp(rule->geo_ip, "!cn") && cn == 1) return 0; /* 未知(-1)不阻拦!cn */
}
if (rule->geo_site[0]) {
    int cn = geo_site_is_cn(host);
    if (!strcmp(rule->geo_site, "cn") && cn != 1) return 0;
    if (!strcmp(rule->geo_site, "!cn") && cn == 1) return 0;
}
```

`geo_host_is_cn` 约束：`getaddrinfo` 取首个结果转字符串调 `geo_ip_is_cn`；成功结果缓存 5 分钟（固定数组 256 项 + 环形覆盖即可，YAGNI）；DNS 失败不缓存、返回 -1；`getaddrinfo` 在事件循环线程是阻塞调用，常见解析 <100ms 可接受（plan 注明后续可优化为异步）。

- [ ] **Step 1: 写 failing 单测（`test_router.c` 追加）**

```c
static void test_rule_geo_ip_cn(void **s) {
    (void)s;
    /* 预置：geo 表含 1.2.3.0/24；host 传 IP 字面量走直查，不依赖 DNS */
    rule_t r; memset(&r, 0, sizeof r);
    r.enabled = 1; r.priority = 100; r.upstream_id = 5;
    strcpy(r.geo_ip, "cn");
    router_t rt; router_init(&rt, "direct", 1);
    router_add_rule(&rt, &r);
    assert_int_equal(router_select(&rt, "1.2.3.9", 80, 0, NULL), 5);
    assert_int_equal(router_select(&rt, "9.9.9.9", 80, 0, NULL), -1);
    router_free(&rt);
}
```

（测试 setup 里先 `geo_init()` + 构造迷你 dat 并 `geo_load()`；teardown `geo_free()`。IP 字面量路径保证单测不碰网络。）

- [ ] **Step 2: 运行确认失败**

Run: `ctest --test-dir build -R test_router -V`
Expected: FAIL（`geo_ip` 字段不存在编译失败）

- [ ] **Step 3: 实现字段 + 匹配 + `geo_host_is_cn`**

- [ ] **Step 4: 运行通过**

Run: `cmake --build build -j4 && ctest --test-dir build`
Expected: 全过

- [ ] **Step 5: Commit**

```bash
git add include/rybaproxy/router.h src/router/router.c src/geo/geo.c include/rybaproxy/geo.h tests/unit/test_router.c
git commit -m "feat(router): geo_ip/geo_site rule conditions with DNS resolve"
```

---

### Task 4: 规则 API 透传 + DB 持久化两字段

**Files:**
- Modify: `src/web/web_api.c`（rules GET/POST/PUT 加 `geo_ip/geo_site`；非法值 400）
- Modify: `src/db/db.c`（`rules` 表 `ALTER TABLE` 加两列；INSERT/UPSERT 带上）
- Test: `tests/unit/test_web_api.c`（追加透传 + 非法值单测）

**Interfaces:**
- Consumes: Task 3 的 `rule_t.geo_ip/geo_site`。
- Produces: API 字段（Task 5 页面消费 `geo_ip/geo_site` 字符串）。

- [ ] **Step 1: 写 failing 单测**

```c
static void test_rule_geo_validation(void **s) {
    (void)s;
    /* POST 非法值 → 400；合法 cn → 201 且 GET 可见（走内存 srv + db 双重断言） */
}
```

（执行者按 `test_web_api.c` 现有 `web_upstreams_update` 用例风格展开：构造 `server_ctx_t` 调分发或直接调 helpers，断言 status 400/201。）

- [ ] **Step 2: 运行确认失败**

Run: `ctest --test-dir build -R test_web_api -V`
Expected: FAIL

- [ ] **Step 3: 实现**
  - `db.c` 建表 SQL 后追加：`ALTER TABLE rules ADD COLUMN geo_ip TEXT DEFAULT ''`（`sqlite3_exec` 忽略已存在错误，即 `rc != OK && rc != DUPLICATE` 才报错；用 `db_exec_raw` 包一层即可）。
  - rules INSERT/UPSERT SQL 加两列（沿用现有 `'转义` 拼接风格，值域仅 `cn/!cn/空`，服务端已校验）。
  - `web_api.c` 三处：POST 解析校验（`strcmp` 白名单），PUT 同，GET 输出 `cJSON_AddStringToObject(o,"geo_ip",r->geo_ip)`。
  - 校验函数放 `web_api.c` 静态：`static int valid_geo(const char *s){ return !s||!*s||!strcmp(s,"cn")||!strcmp(s,"!cn"); }` 空视为合法（不限）。

- [ ] **Step 4: 运行通过**

Run: `cmake --build build -j4 && ctest --test-dir build`
Expected: 全过

- [ ] **Step 5: Commit**

```bash
git add src/web/web_api.c src/db/db.c tests/unit/test_web_api.c
git commit -m "feat(api): rule geo_ip/geo_site passthrough + db columns"
```

---

### Task 5: `/api/geo/*` 三端点（status / download / check）

**Files:**
- Modify: `src/web/web_api.c`（`web_api_dispatch` 加分支）
- Modify: `src/geo/geo.c`（下载函数 `geo_download(const char *dir, char *err, size_t errsz)`：curl 风格用 `popen("curl -fsSL ...")` 或纯 socket？→ 用 `popen curl`，60s 超时，tmp+rename 原子落盘，成功调 `geo_load`）
- Test: `tests/unit/test_web_api.c`（status/check 单测；download 只测参数校验与失败路径，不碰真网）

**Interfaces:**
- Consumes: Task 2 的 `geo_load/geo_ip_count/geo_site_count`，Task 3 的 `geo_host_is_cn`。
- Produces: 端点 `GET /api/geo/status` / `POST /api/geo/download` / `GET /api/geo/check?host=`（Task 6 页面消费）。

响应形状：

```json
GET /api/geo/status → {"data":{"geoip":{"exists":true,"size":12345,"mtime":1730000000,"cn_count":123},"geosite":{...}}}
POST /api/geo/download → {"data":{"ok":true}} / 502 {"error":{"code":"DOWNLOAD_FAILED","message":"..."}}
GET /api/geo/check?host=qq.com → {"data":{"host":"qq.com","ips":["..."],"geoip_cn":true,"geosite_cn":true,"matched_rule":1,"upstream":{"id":0,"name":"direct"}}}
```

- [ ] **Step 1: 写 failing 单测（status 空目录 + check 私网 IP + 缺 host 参数 400）**

- [ ] **Step 2: 运行确认失败**

- [ ] **Step 3: 实现**
  - `geo_download`：URL 硬编码两份 dat 的 raw 地址（plan 注明换源只改这两行）；`popen` 调 `curl -fsSL --max-time 60 -o tmp`；双文件都成功才 rename + `geo_load`；任一失败保留旧文件，`err` 写原因。
  - `check`：`parse_id` 旁加 `query_param(query,"host")` 小 helper（无则复用现有 `strstr` 解析）；IP 字面量直接查，域名走 `getaddrinfo` 取全部 IP（最多 4 个返回）+ `geo_site_is_cn` + `router_select` 得 `matched_rule/upstream`（需持 `srv->lock` 读规则与 upstreams 表）。
  - 下载是同步阻塞（文件 ~10MB，60s 内返回；按钮置灰由前端做）。

- [ ] **Step 4: 运行通过（含 `curl --version` 存在性检查，CI 缺 curl 则 download 单测跳过失败路径）**

- [ ] **Step 5: Commit**

```bash
git add src/web/web_api.c src/geo/geo.c include/rybaproxy/geo.h tests/unit/test_web_api.c
git commit -m "feat(api): /api/geo status/download/check endpoints"
```

---

### Task 6: 页面——规则下拉 + geo 条件 + 管理卡 + 检测页

**Files:**
- Modify: `src/web/web_page.h`（规则编辑器/列表/管理卡/检测 tab）
- Test: `tests/unit/test_web_page.c`（字符串断言：`name="upstream_id"` 的 select、geo 下拉、`geo/check`、`geo/status` 出现；手填数字 input 消失）

**Interfaces:**
- Consumes: Task 4/5 的 API。
- Produces: 无（终端交付）。

改动清单（逐项照做）：

1. 规则编辑器 `upstream_id` number input → `<select name="upstream_id">`，option 由 `upstreams` 数组渲染 `name(id)`；打开编辑器时选中当前值。
2. 新增两组 select：`name="geo_ip"`（不限/`cn`→`geoip:cn`/ `!cn`→`非geoip:cn`）、`name="geo_site"` 同理；保存 payload 带两字段。
3. 规则列表 `upstream_id` 数字列 → `upstreams.find` 显示名字（找不到显示 `id(N)`）。
4. 出口节点区下方加 Geo 管理卡：两行状态（调 `/api/geo/status`）+ "下载/更新"按钮（POST，禁用态处理中）。
5. 顶栏加"检测" tab：输入框 + 按钮，结果区展示 `check` 返回（解析 IP、geoip/geosite 命中、命中规则与出口）。
6. 规则区顶部加标准配法提示小字（spec §8 三行）。

- [ ] **Step 1: 写 failing 单测（断言新字符串存在、旧 number input 不存在）**

- [ ] **Step 2: 运行确认失败**

- [ ] **Step 3: 实现页面改动**

- [ ] **Step 4: 运行通过 + 真机看一眼（`GET /` 200，打开规则编辑器截图/肉眼确认下拉与管理卡）**

- [ ] **Step 5: Commit**

```bash
git add src/web/web_page.h tests/unit/test_web_page.c
git commit -m "feat(web): geo rule selects, geo card, check page, upstream dropdown"
```

---

### Task 7: 真机 e2e（真实 dat + hk 链路）+ 全量回归

**Files:** 无新增（验证型 Task）。

- [ ] **Step 1: 下载真实 dat**：起本地实例，调 `POST /api/geo/download`，确认 `status` 显示条目数 > 0。
- [ ] **Step 2: 配标准规则**：`geo_ip=cn→direct`、`geo_site=cn→direct`（priority 100），默认出口 `hk`。
- [ ] **Step 3: 验证分流**：`qq.com` 经 ryba 应走 direct（内容/出口为本地）；`ifconfig.me` 应走 hk（出口 `85.8.151.20`）。`GET /api/geo/check?host=` 两者各查一次，结果一致。
- [ ] **Step 4: 全量回归**：`cmake --build build -j4 && ctest --test-dir build` 全过。
- [ ] **Step 5: Commit（空提交记验证）**

```bash
git commit --allow-empty -m "test(e2e): geo split verified with real dat + hk chain"
```

---

## Self-Review

1. **Spec 覆盖**：§2.1 字段→Task 3/4；§2.2 下载解析→Task 2/5；§2.3 语义→Task 1/2/3；§2.4 DNS→Task 3；§3 API→Task 4/5；§4 界面→Task 6（含 upstream 下拉）；§5 错误处理→Task 2/3/5（缺文件降级、下载保留旧、DNS 未知策略、400 校验）；§6 测试→各 Task 单测 + Task 7 e2e；§8 配法提示→Task 6.6。✅ 无遗漏。
2. **Placeholder 扫描**：Task 2 Step 3 允许执行者写完整代码但给了结构约束与格式定义，无 "TODO/类似 Task N" 表述；Task 5 curl 可用性有显式检查步骤。✅
3. **类型一致性**：`geo_ip_is_cn/geo_site_is_cn/geo_host_is_cn` 统一 `1/0/-1` 三值；`rule_t.geo_ip[16]/geo_site[16]`；API 字段名 `geo_ip/geo_site` 全链路一致；DB 列名同 API。✅
