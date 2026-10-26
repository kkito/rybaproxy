# 协议规范

## 1. HTTP 代理

### 1.1 普通请求（absolute URI）

```
GET http://example.com/path HTTP/1.1
Host: example.com
```

处理：
- 解析 method、absolute URI、HTTP version
- 提取 Host（优先 URI host，其次 Host 头）
- 选择 upstream
- 建立到目标的连接（或经 upstream）
- 转发原始请求（可重写 `Via`、`X-Forwarded-For`）

### 1.2 CONNECT 隧道

```
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
```

响应：
- 成功：`HTTP/1.1 200 Connection Established\r\n\r\n`
- 失败：`HTTP/1.1 502 Bad Gateway\r\n\r\n` 等

之后进入双向字节流。

### 1.3 Hop-by-hop 头处理

移除/不转发：`Connection`、`Proxy-Connection`、`Keep-Alive`、`Transfer-Encoding`（按需）、`TE`、`Trailer`、`Upgrade`（CONNECT 除外）。添加 `Via: 1.1 rybaproxy`。

### 1.4 认证

v1 支持可选的 Proxy-Authorization Basic（客户端连网关时），用于管理端/代理端访问控制。配置 `proxy_auth_enabled`。

## 2. SOCKS5（RFC 1928 + RFC 1929）

### 2.1 握手

客户端 -> 服务器: `05 01 00`（无认证）或 `05 02 00 02`（用户名/密码）
服务器 -> 客户端: `05 00` 或 `05 02`，或 `05 FF`（无支持方法）

### 2.2 用户名/密码（RFC 1929）

客户端: `01 ulen uname plen passwd`
服务器: `01 00` 成功 / `01 01` 失败

### 2.3 请求

客户端: `05 cmd rsv atyp dst.addr dst.port`
- cmd: `01`=CONNECT（支持），`02`=BIND（拒绝），`03`=UDP ASSOCIATE（拒绝）
- atyp: `01`=IPv4, `03`=域名, `04`=IPv6

服务器回复: `05 rep rsv atyp bnd.addr bnd.port`，rep=0 成功。

### 2.4 仅 TCP CONNECT

BIND/UDP 返回 rep=0x07（命令不支持）或 0x08。

## 3. 上游代理协议

### 3.1 direct

直接 TCP 连接目标 host:port。

### 3.2 http（上游 HTTP 代理）

- CONNECT target:port -> 等待 `200` -> 隧道
- 普通请求：转发原始请求到上游（绝对 URI）

支持 Basic 认证（`Proxy-Authorization`）。

### 3.3 socks5（上游 SOCKS5）

按 RFC 1928/1929 与上游握手，CONNECT 目标。

## 4. Nginx 集成

### 4.1 推荐 nginx 配置（普通 HTTP 转发）

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;  # 网关 HTTP 代理端口或专用入口
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### 4.2 网关识别可信代理

配置 `trusted_proxies`（CIDR 列表）。仅来自这些 IP 的 `X-Forwarded-*` 被信任；否则使用 socket peer IP。

### 4.3 限制

- nginx 不支持 HTTP CONNECT 代理；CONNECT 需直连网关端口或使用 `stream` 模块做 TCP 透传。
- 若需 nginx 做 TLS 终止 + CONNECT，使用 `stream { server { proxy_pass ...; } }` 透传到网关 SOCKS5/HTTP 端口。

## 5. 管理 API 鉴权

- Bearer token：`Authorization: Bearer <token>`
- 或 Basic Auth（配置）
- 未鉴权请求返回 401
