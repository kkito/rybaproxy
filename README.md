# rybaproxy

> 目标：像 Rybakina 一样稳定 —— 没有起伏，没有波动。

纯 C 实现的代理网关：HTTP / SOCKS5 代理、多上游按域名/IP 选择、nginx 后面部署、Web 管理与细粒度 SQLite 统计（保留 3 个月）。

设计文档见 `docs/`。

## 快速开始（规划）

```sh
make
./build/rybaproxy -c docs/../config.json  # 待实现
```

当前阶段：设计文档已完成，代码实现待开始。
