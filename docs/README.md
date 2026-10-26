# rybaproxy — 代理网关（纯 C 实现）设计文档

## 1. 目标

在本地实现一个**代理网关**，对外提供：

- HTTP 代理（支持 `GET/POST/...` 转发与 `CONNECT` 隧道）
- SOCKS5 代理
- 可部署在 nginx 后面：nginx 将外部请求转发给网关，网关再按规则通过上游代理或本地网络转发出去

网关可接入**多个上游代理**，按域名 / IP（以及端口、协议等）选择使用哪个代理，或直接走本地网络。

同时提供：

- Web 管理界面（规则、上游代理、实时连接、日志）
- 细粒度数据统计，使用 SQLite 持久化，**仅保留最近 3 个月**的明细数据

实现语言：**纯 C（C11）**。测试覆盖完整（单元 + 集成 + 模糊测试）。

## 2. 非目标（v1 不做）

- 不做 HTTPS MITM / 流量解密
- 不做用户级配额计费（仅统计）
- 不做集群/多节点同步
- 不做 IPv6 主动优先（支持但不作为默认）
- 上游代理仅支持 TCP（HTTP 代理、SOCKS5）；TLS 包裹的上游（HTTPS proxy）列为 v2

## 3. 术语

| 术语 | 含义 |
|---|---|
| Gateway / 网关 | 本程序 |
| Client | 最终用户/调用方 |
| Upstream Profile / 上游档案 | 一个可用的出站通道：`direct` / `http` / `socks5` |
| Rule / 规则 | 域名/IP 等条件 -> 上游档案 |
| Session | 一次客户端连接（HTTP CONNECT 隧道或 SOCKS5 连接算一个；普通 HTTP 请求按请求计） |
| Nginx 模式 | 网关位于 nginx 反向代理之后，通过 `X-Forwarded-*` 等头识别真实客户端 |

## 4. 部署形态

1. **直连模式**：客户端直接连网关 HTTP/SOCKS5 端口。
2. **Nginx 后面**：外部 -> nginx -> 网关。nginx 可做 TLS 终止、访问控制、限流；网关读取 `X-Forwarded-For`、`X-Forwarded-Proto`、`X-Real-IP`。
3. **混合模式**：管理端口仅本机/内网；代理端口对外。

## 5. 文档索引

- `architecture.md` — 模块与数据流
- `protocols.md` — 协议细节
- `routing.md` — 路由/选择规则
- `data-model.md` — SQLite 表结构与保留策略
- `web-api.md` — Web 界面与 REST API
- `config.md` — 配置文件
- `testing.md` — 测试策略
- `build.md` — 构建与依赖
