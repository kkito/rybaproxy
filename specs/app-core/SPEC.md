---
id: ryba-core
type: module-design
status: active
title: 应用内核（配置/进程/认证）
parent: ryba-architecture
---

## Responsibility

进程形态与横切基础：JSON 配置加载校验与热重载、daemon 化、pidfile 单实例、日志落盘、启动信息屏、路径解析。

## Boundary

- Owns: `src/main.c`、`src/core/`（config、daemon、log、pidfile、startup_info、strutil）、`include/rybaproxy/paths.h`。
- Serves: 其余所有模块只消费 `config_t` 与 `ryba_ensure_dir`，不反向依赖。

## Decisions

- `start` 前台默认打印一屏基本信息；`-d` 后台化时父进程等就绪才返回，失败不谎报成功。
- 配置键兼容两层：`stats.log_file`/`stats.log_level` 与顶层 `log_file`/`log_level` 同义；`stats.db_path` 默认指向新库名。
- 日志级别解析为纯函数 `log_level_parse`（大小写不敏感，未知回 INFO）；暂无轮转（用户确认的约束）。
- POSIX 特性宏在 CMake 顶层统一注入（`_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE=1`），由 `test_portability` 编译期守卫。
