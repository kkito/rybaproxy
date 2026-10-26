# 路由与上游选择

## 1. 选择流程

```
输入: target_host, target_port, protocol, client_ip
1. 若 target_host 为 IP：先匹配 IP/CIDR 规则，再端口/协议
2. 若为域名：
   a. 匹配域名规则（exact / suffix / wildcard）
   b. 可选：DNS 解析后匹配 IP 规则（配置 resolve_for_routing）
   c. 端口/协议过滤
3. 按 priority 降序，取第一条 enabled 规则
4. 无匹配 -> default_upstream（配置）
5. 若选中的 upstream 不可用且 fallback_to_direct=1 -> direct
```

## 2. 匹配语法

### 2.1 域名

- `example.com`：精确
- `*.example.com`：任意子域（不匹配 example.com 本身）
- `.example.com`：example.com 及其子域
- `*`：任意域名

大小写不敏感；自动 trim 尾部点。

### 2.2 IP / CIDR

- `192.168.1.10`
- `10.0.0.0/8`
- `192.168.0.0/16`
- 支持 IPv4；IPv6 v2

### 2.3 端口

- `0` 或空：任意
- 单个：`443`
- 范围：`8000-9000`（可选 v2）

### 2.4 协议

`any` / `http` / `https` / `socks`（按目标端口或 ALPN 不解析；这里指客户端接入协议 http/socks5 可选）

## 3. 规则管理

- 配置文件启动时加载
- Web API 运行时 CRUD，写入 SQLite `rules` 表并热重载
- 变更审计：记录 who/when（v1 简单日志）

## 4. 冲突与优先级

- priority 高者优先；相同 priority 按 id 升序
- disabled 规则跳过
- 规则缓存：每次匹配遍历内存数组（规则数通常 < 1000，O(n) 可接受）；>1000 时编译为 trie（v2）

## 5. 直连判定

`direct` profile 表示不使用任何上游代理，本地网络直连目标。可配置 `direct.bind_interface` / `direct.source_ip`。

## 6. 失败与重试

- 连接上游失败：重试 1 次（可配置）；仍失败则尝试 fallback
- 不对幂等性做保证（隧道场景不重试已建立连接）
