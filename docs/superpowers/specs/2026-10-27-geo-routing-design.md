# Geo 分流设计（geoip / geosite）

- 日期：2026-10-27
- 范围：规则新增 `geo_ip / geo_site` 条件（`cn / !cn`），IP 库界面手动下载，检测小页面
- 生态：v2ray dat（Loyalsoldier `geoip.dat` + `geosite.dat`），自研小解析器，不引入 libmaxminddb

## 1. 背景与目标

当前 `rule_t` 只有 `domain_pattern`（手写单条）、`ip_cidr`（且匹配的是 **client_ip**，目标站 IP 不参与选路）、端口、协议。
目标：配出"国内直连、国外走代理"，语义对标 v2ray：

- `geoip:cn` = 中国 IP 段集合；`geosite:cn` = 中国域名集合
- 标准配法 = 两条 CN 规则（高优先级 → direct）+ 兜底 `default_upstream` 走代理
- "非 CN"不需要单独表达：高优先级 CN 规则未命中、掉进兜底，自然就是国外走代理
- `!cn` 取反保留给特殊场景（如"非 CN 且 443 → 另一条专线"）

## 2. 数据模型

### 2.1 `rule_t` 新增字段

```c
char geo_ip[16];    // ""=不限 | "cn" | "!cn"
char geo_site[16];  // ""=不限 | "cn" | "!cn"
```

- 与现有条件（domain_pattern / ip_cidr / port / protocol）为 AND 关系：所有非空条件都满足才命中。
- DB `rules` 表加 `geo_ip TEXT DEFAULT ''`, `geo_site TEXT DEFAULT ''` 列（`ALTER TABLE` 兼容老库）。
- Web API：rules 的 GET/POST/PUT 透传两字段；`country` 之类旧名不引入，避免双轨。

### 2.2 geo 数据文件

- 来源：Loyalsoldier GitHub raw 的 `geoip.dat` + `geosite.dat`（免 key，内容每周跟 MaxMind 同步）。
- 存放：db 同目录，`geoip.dat` / `geosite.dat`，路径可在设置里改，默认与 `db_path` 同目录。
- 格式：v2ray 私有 protobuf/varint 编码，自研解析器（~300 行，格式公开可参照实现），无新第三方依赖。
- 内存结构：
  - IP：全量 CIDR（含 IPv4/IPv6）按地址排序，二分查找；顺手补齐现有 `match_cidr` 只支持 IPv4 的短板（geo 路径走新实现，老 `ip_cidr` 语义不动）。
  - 域名：清单建成后缀 Trie，支持 exact / 子域名包含 / regex 三类（regex 用 libc `regcomp` 预编译）。
- 私网 IP（10/8、172.16/12、192.168/16、127/8、::1、fc00::/7 等）视为命中 `cn`（对标 v2ray `geoip:private` 进 direct）。

### 2.3 匹配语义

- `geo_ip=cn`：目标 IP 在 CN 段（含私网）→ 满足；DNS 失败 / 未知段 → **不满足**（未知按国外处理）。
- `geo_ip=!cn`：与上取反；未知段 → **满足**（宁可绕路走代理）。
- `geo_site=cn`：目标域名命中清单（含子域名）→ 满足；IP 直连请求（无域名）→ 不满足。
- `geo_site=!cn`：取反；IP 直连 → 满足。
- 空字段 = 不限（不参与 AND）。
- 文件缺失/损坏/未下载：所有含 geo 条件的规则直接不命中并打日志，转发流程不受影响（降级为当前行为）。

### 2.4 选路流程（含 DNS）

```
请求 host(:port)
  → 规则按 priority 逐条 rule_matches()
      geo_ip 非空？ 需要目标 IP：
        host 是 IP 字面量 → 直接用
        host 是域名 → DNS 解析（5 分钟 TTL 小缓存）→ IP
        解析失败 → 视为未知（cn 不命中，!cn 命中）
      geo_site 非空？ 查域名 Trie
  → 命中最高优先级规则 → upstream_id → 出口拨号
  → 无命中 → default_upstream（兜底）
```

- DNS 用系统 resolver（`getaddrinfo`），结果缓存 5 分钟；缓存 key 为域名，value 为首个 IP + 是否命中 CN（避免每次请求都查库）。
- 性能：二分 + Trie 均为微秒级，常驻内存，无 IO。

## 3. 接口设计

### 3.1 规则 API（现有接口扩展字段）

- `GET /api/rules`：每条多出 `geo_ip`, `geo_site`。
- `POST /api/rules`, `PUT /api/rules/:id`：接受两字段，仅允许 `"" / "cn" / "!cn"`，非法值 → 400 `BAD_REQUEST`。

### 3.2 Geo 管理 API（新增）

- `GET /api/geo/status` → `{ geoip: {exists,size,mtime,cn_count}, geosite: {...} }`（文件不存在则 `exists:false`）。
- `POST /api/geo/download` → 后台下载两个文件（~10MB 级，设 60s 超时），原子落盘（tmp + rename），成功后重载内存；返回 `{ok}` 或 `{error}`。下载失败保留旧文件。
- `GET /api/geo/check?host=<域名或IP>` → `{ host, ips:[...], geoip_cn:bool, geosite_cn:bool, matched_rule:{id,...}|null, upstream:{id,name}|null }`，即"按当前规则会走哪条→哪个出口"。

## 4. 界面设计（三处）

CSS 不动，只改 JS（沿用 Task4 模式，`web_page.h` 内联）：

1. **规则编辑器**：
   - "上游 ID"手填数字框 → **出口节点下拉框**（option 显示 `direct/hk/...` 名字，value 存 id；新建默认选中 default）。
   - 新增"国家(IP)"下拉：不限 / geoip:cn / 非geoip:cn；"国家(域名)"下拉：不限 / geosite:cn / 非geosite:cn。
2. **规则列表**：`upstream_id` 裸数字列改为显示出口节点名字（未知 id 显示 `id(N)` 兜底）。
3. **IP 库管理卡**（放"出口节点"区下方或设置页）：两行显示 geoip/geosite 状态（存在/大小/更新时间/CN 条目数）+ 一个"下载/更新"按钮（纯手动，无定时）。下载中按钮置灰，失败 toast。
4. **新增"检测"小页**（顶栏 tab 加一项"检测"）：输入框 + 按钮，结果区显示解析 IP、geoip/geosite 命中情况、命中规则与出口。调用 `GET /api/geo/check`。

## 5. 错误处理

| 场景 | 行为 |
|---|---|
| dat 文件缺失/损坏 | 含 geo 条件规则不命中 + `web_log_push(WARN)`；转发不受影响 |
| 下载失败（网络/超时/校验） | 保留旧文件，API 返回 502 + 错误信息，界面 toast |
| DNS 解析失败 | 该次按未知处理（cn 不命中 / !cn 命中），不缓存失败结果 |
| 非法 geo 值写入 | 400 BAD_REQUEST |

## 6. 测试计划

- 单测（cmocka，沿用 `add_ryba_test`）：
  - dat 解析：手工构造迷你 dat（含 varint/CIDR/域名三类条目）→ 解析出条目数与内容正确。
  - `geo_match` 语义：cn 命中 / !cn 取反 / 私网视为 cn / 未知段行为 / IP 字面量直查。
  - `check` 接口：给定 fake 内存数据，host 分别命中 geoip / geosite / 都不命中。
- e2e（真机 + 真实 dat）：下载真实文件后 `qq.com` → CN 走 direct，`ifconfig.me` → 非 CN 走代理；断网/DNS 失败降级不断流。
- 回归：`ctest 11/11`（现有）+ 新增用例全过。

## 7. 非目标（YAGNI）

- 不做自动更新/定时任务（纯手动按钮）。
- 不做多国家选择（只有 cn / !cn；后续加 `us` 等只需放宽校验 + dat 里已有全量国家段）。
- 不做 DoH/代理 DNS（用系统 resolver；污染场景后续再议）。
- 不重构老 `ip_cidr`（client_ip 语义保持不动，避免误伤现有规则）。

## 8. 标准配法示例（写进界面提示）

```
规则1: 国家(IP)=geoip:cn, 优先级100 → direct
规则2: 国家(域名)=geosite:cn, 优先级100 → direct
默认出口: hk   ← 国外流量兜底走这里
```
