# 测试策略

## 1. 目标与铁律

- 核心判定逻辑用**无状态纯函数**写，测试就是“构造输入 → 断言输出”，不依赖进程残留状态。
- **单测零网络**（AGENTS.md §4）：禁止 DNS 解析、curl 下载、访问外部服务；需要时用可注入的 fake。
- 核心模块行覆盖率目标 ≥ 80%。

## 2. 框架

- C 侧：**cmocka**（vcpkg），`tests/unit/test_<module>.c` → 一个可执行文件 + 一个 ctest 用例。
- Web 侧：**vitest + happy-dom**（全局安装，`NODE_PATH=$(npm root -g)`），另加 `tsc --noEmit` 类型检查。

## 3. 单元测试清单

C 单测（每个 `tests/unit/test_<module>.c` 对应一个 ctest 用例）：

| 测试 | 覆盖点 |
|---|---|
| `test_smoke` | 基本装配 |
| `test_config` | 配置加载/校验、默认值 |
| `test_router` | 域名 wildcard / CIDR / 端口 / 优先级 / fallback |
| `test_auth` | 用户认证与凭据解析 |
| `test_socks5` | 握手、atyp、拒绝命令 |
| `test_http_proxy` | request line、headers、CONNECT、上游 HTTP/SOCKS5 握手 |
| `test_stats` | 事件序列化、聚合、保留期边界 |
| `test_db` | SQLite schema / 写入 / 只读聚合查询 |
| `test_upstream_probe` | 上游探活判定 |
| `test_web_api` | REST 接口的请求/响应形状 |
| `test_geo` | IP 库判定、空库未知、分流口径 |
| `test_portability` | 编译期 `#error` 守 `_POSIX_C_SOURCE` 等宏（否则 glibc 藏 POSIX 符号） |
| `test_strutil` | 字符串工具纯函数 |
| `test_pidfile` | pidfile 读写、单实例互斥 |
| `test_daemon` | 守护进程化、就绪握手、端口占用失败路径 |
| `test_startup_info` | 启动信息渲染 |
| `test_dns` | 解析器注入、缓存、日志 |
| `test_web_page` | 内嵌页面产物（真实 API 路径、DOM 钩子、无 `Math.random` 假数据、保留 `refreshLive` 等符号） |

前端：`web_vitest`（含 WebComponent 与纯 render 函数）、`web_tsc`（`tsc --noEmit -p web/tsconfig.json`）。
新增测试时往 `tests/CMakeLists.txt` 加一行 `add_ryba_test()` 即可，无需同步本文件的任何计数。
全局 `vitest`/`happy-dom`/`tsc` 缺失时这两项在 configure 阶段静默跳过。

## 4. 零网络的做法

- 网络边界可注入：生产走真实实现，测试注入 fake —— `dns_set_resolver()`、`geo_set_resolver()`（NULL = 系统 DNS）。
- 空状态/空条件必须短路在网络调用**之前**：空 IP 库直接报“未知”不解析（`geo_host_is_cn` 先查 `loaded`）；
  空 geo 条件跳过查询（`rule_matches` 先判 `rule->geo_ip[0]`）。
- 用“哨兵 mock”（被调用即 `fail_msg`）锁住零网络：空库用例、IP 字面量用例、纯 `geo_site` 用例都注入哨兵。
- 测试钩子：`geo_test_reset()` 复位缓存与 resolver 注入。

## 5. 跑测试

```sh
cmake --build build -j4 && ctest --test-dir build --output-on-failure
```

单个用例定位（本机 DNS 超时曾伪装成“中间一个测试慢”，先怀疑 DNS 再怀疑逻辑）：

```sh
CMOCKA_TEST_FILTER=test_geo_host_is_cn ./build/tests/test_geo
cd web && NODE_PATH=$(npm root -g) vitest run tests/format.test.ts
```

## 6. 命名

`tests/unit/test_router.c::test_route_domain_wildcard` —— 一个测试只断言一个行为，
失败信息里要说清“期望什么 / 实际什么”。

## 7. 暂未覆盖（v1 不做）

集成测试（真起网关跑 curl）、模糊测试（libFuzzer/AFL）、并发压力测试目前**尚未落地**，
`tests/integration/`、`tests/fuzz/` 目录不存在。需要时按 `docs/testing.md` 之外的独立计划补。
