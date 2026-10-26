# 测试策略

## 1. 目标

- 核心模块单元测试覆盖率 ≥ 80%（行）
- 解析器（HTTP/SOCKS5/JSON/路由）模糊测试
- 集成测试覆盖主要用户路径
- 无内存泄漏（ASan/LSan）
- 并发/压力测试

## 2. 单元测试（tests/unit）

框架：Unity（vendored）。每个模块对应 `test_<module>.c`。

覆盖：
- `matcher`：域名 wildcard、CIDR、端口、优先级
- `router`：选择逻辑、fallback
- `http_proxy` 解析：request line、headers、CONNECT
- `socks5`：握手、atyp、拒绝命令
- `upstream`：HTTP/SOCKS5 客户端握手状态机
- `stats`：事件序列化、聚合
- `config`：加载/校验
- `retention`：日期边界

## 3. 集成测试（tests/integration）

Python 驱动（或 shell），启动网关，使用：
- `curl -x http://127.0.0.1:8080 http://httpbin.org/get`
- `curl --socks5 127.0.0.1:1080 https://example.com`
- CONNECT 隧道：`curl -x http://... -p https://...`
- nginx 联动：启动 nginx 反代到网关，验证 XFF

使用本地 mock 上游/目标服务器（Python http.server）避免外网依赖。

## 4. 模糊测试

- libFuzzer 或 AFL++ 对 HTTP 请求解析、SOCKS5 解析、JSON config
- 语料库 `tests/fuzz/corpus/`
- CI 运行 60s/目标

## 5. 性能测试

- `wrk`/`vegeta`：HTTP 代理吞吐
- `iperf` 风格：CONNECT 隧道吞吐
- 目标：单核 1 Gbps 小包转发（参考）

## 6. 并发与竞态

- 规则热重载期间并发请求（TSan）
- 统计队列满时行为

## 7. CI

- GitHub Actions：build + unit + integration + asan + coverage 上传
- 失败阻断

## 8. 测试命名

`tests/unit/test_router.c::test_route_domain_wildcard`
