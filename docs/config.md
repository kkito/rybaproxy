# 配置文件

格式：JSON（便于解析；使用内置 cJSON）。默认路径 `/etc/rybaproxy/config.json`，可用 `-c` 指定。

## 示例

```json
{
  "log_level": "info",
  "log_file": "/var/log/rybaproxy/rybaproxy.log",

  "proxy": {
    "http_listen": "0.0.0.0:8080",
    "socks5_listen": "0.0.0.0:1080",
    "proxy_auth_enabled": false,
    "proxy_username": "",
    "proxy_password": ""
  },

  "web": {
    "listen": "127.0.0.1:9090",
    "auth_token": "change-me",
    "web_root": ""
  },

  "limits": {
    "max_connections": 10240,
    "idle_timeout_sec": 300,
    "max_session_sec": 3600,
    "connect_timeout_sec": 10,
    "dns_timeout_sec": 5
  },

  "routing": {
    "default_upstream": "direct",
    "resolve_for_routing": false,
    "fallback_to_direct": true,
    "retry_connect": 1
  },

  "nginx": {
    "trusted_proxies": ["127.0.0.1/32", "10.0.0.0/8"],
    "use_x_forwarded_for": true
  },

  "direct": {
    "bind_interface": "",
    "source_ip": ""
  },

  "stats": {
    "db_path": "~/.local/rybaproxy/rybaproxy.db",
    "log_file": "~/.local/rybaproxy/rybaproxy.log",
    "log_level": "info",
    "pid_file": "~/.local/rybaproxy/rybaproxy.pid",
    "geo_cache_size": 512,
    "retention_days": 90,
    "aggregate_retention_days": 365,
    "queue_size": 65536,
    "batch_size": 256,
    "flush_interval_ms": 200,
    "record_http_requests": true
  },

  "upstreams": [
    { "name": "direct", "type": "direct" },
    { "name": "corp-http", "type": "http", "host": "proxy.corp.com", "port": 8080,
      "username": "u", "password": "p" },
    { "name": "corp-socks", "type": "socks5", "host": "10.0.0.5", "port": 1080 }
  ],

  "rules": [
    { "name": "internal", "priority": 200, "domain_pattern": ".corp.com",
      "upstream": "direct" },
    { "name": "block-ads", "priority": 150, "domain_pattern": "*.doubleclick.net",
      "upstream": "direct" },
    { "name": "default-proxy", "priority": 10, "domain_pattern": "*",
      "upstream": "corp-http" }
  ]
}
```

## 1. 命令行

```
rybaproxy [-c config] [-t]        # -t 测试配置并退出
           [-d]                   # daemonize
           [-v]                   # version
```

## 2. 热重载

- `SIGHUP`：重新加载配置文件（upstreams/rules/settings）
- Web API `POST /api/rules/reload`

## 3. 环境变量覆盖

- `RYBAPROXY_CONFIG`
- `RYBAPROXY_LOG_LEVEL`
