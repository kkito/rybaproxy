# rybaproxy

> 目标：像 Rybakina 一样稳定 —— 没有起伏，没有波动。

纯 C 实现的代理网关：HTTP / SOCKS5 代理、多上游按域名/IP 选择、nginx 后面部署、Web 管理与细粒度 SQLite 统计（保留 3 个月）。

设计文档见 `docs/`。

## 快速开始

```sh
make
./build/rybaproxy -c config.json          # 前台运行（同 rybaproxy start）
```

### 命令行

```
Usage: rybaproxy [start|stop] [options]

Commands:
  start                start the proxy in the foreground (default)
  stop                 stop the running instance (via pidfile)

Options:
  -c, --config FILE    config file path
  -d, --detach         run as a background daemon (start only)
  -h, --help           show this help
  -v, --version        show version
```

- `rybaproxy start` 前台运行，启动时打印一屏基本信息（版本、路径、监听端口、管理页地址、上游、规则、geo 状态）。
- `rybaproxy start -d` 守护进程化，父进程打印 `pid`、管理页地址与日志路径，详细信息写入日志文件。
  父进程会等守护进程真正就绪才返回；守护进程起不来（如端口被占）时父进程报错退出并给出原因，不会谎报成功。
- `rybaproxy stop` 读 `stats.pid_file`（默认 `<数据目录>/rybaproxy.pid`）→ `SIGTERM` → 等 10 秒 → 超时升级 `SIGKILL` → 删 pidfile。本来没在跑也算成功。
- 任何模式都会写 pidfile；已有一个实例在跑时重复启动会被拒绝（提示现有 pid）。
