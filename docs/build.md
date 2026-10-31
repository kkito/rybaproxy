# 构建与依赖

## 1. 依赖管理：vcpkg

C 依赖走 **vcpkg manifest 模式**（`vcpkg.json`），复用本机 vcpkg（默认 `~/vcpkg`）。

| 依赖 | 用途 |
|---|---|
| libevent（core/extra/pthreads） | 事件循环、HTTP 解析、DNS |
| OpenSSL | 上游 TLS / 加解密 |
| sqlite3 | 统计与 geo 数据 |
| cJSON | 配置与 Web API JSON |
| cmocka | 单元测试框架 |
| civetweb（+ssl） | Web 管理界面 HTTP 服务 |
| llhttp | HTTP 代理请求解析 |
| c-ares | 异步 DNS 解析 |

## 2. 前置工具链

```sh
# Debian/Ubuntu
sudo apt-get install -y build-essential pkg-config git curl zip unzip tar \
                        ninja-build autoconf automake libtool bison flex
```

- **CMake ≥ 3.30**（vcpkg 自身要求；Ubuntu 22.04 自带的 3.22 不够，需另装官方二进制或 pip 版）。
  项目本身只要求 3.20，但配 vcpkg toolchain 时会先撞上 vcpkg 的版本检查。
- **Node.js**（构建时必需，非可选）：`find_program(RYBA_NODE_EXECUTABLE node REQUIRED)`，
  缺失直接 configure 失败，不静默降级。Web 侧全局工具链：

  ```sh
  npm install -g esbuild vitest happy-dom typescript
  ```

  不写 `web/package.json`、不提交 `web/node_modules`；CMake 自动执行 `npm root -g` 注入 `NODE_PATH`。

## 3. 构建步骤

```sh
# 1) 安装 vcpkg（若未安装）
git clone https://github.com/microsoft/vcpkg.git ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh

# 2) 配置（manifest 模式，首次会编译并安装全部依赖）
cmake -S . -B build \
  -DCMAKE_TOOLCHAIN_FILE=$HOME/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DCMAKE_BUILD_TYPE=Debug

# 3) 构建
cmake --build build -j"$(nproc)"

# 4) 测试
ctest --test-dir build --output-on-failure
```

或者直接 `make`（等价封装，`VCPKG_ROOT` 默认 `~/vcpkg`）：

```
make            # configure + build
make test       # build + ctest
make clean      # 清掉 build/ build-*/
```

依赖装到 `build/vcpkg_installed/<triplet>/`，只随本次构建存在，不污染系统。

## 4. Web 前端构建（每次构建必经）

前端没有“旧产物”这一说，源码即唯一来源：

```
web/src/app.ts ──esbuild(scripts/build_web.cjs)──> build/web-dist/ryba-web.js
web/index.html + web/style.css ──inline──┐
scripts/gen_web_page.js ─────────────────┴──> build/generated/web_page_gen.h
                                              （WEB_PAGE_HTML_GEN，编译进二进制）
```

- 产物只落 `build/`，不回写源码树。
- 打包不开 minify：单测（`tests/unit/test_web_page.c`）断言产物里保留 `refreshLive`、
  `setInterval(` 等顶层符号，压缩会打断这些断言。
- 细节见 `webhtml.md`。

## 5. 目录

```
rybaproxy/
  CMakeLists.txt      # 含 web 生成链路、sanitizer 开关
  vcpkg.json          # C 依赖清单（manifest）
  include/rybaproxy/  # 公共头（version.h 由 build 生成）
  src/                # core / proxy / routing / dns / geo / stats / web ...
  tests/unit/         # cmocka 单测（每个 .c 一个可执行）
  web/                # index.html / style.css / src/*.ts / tests/*.test.ts
  scripts/            # build_web.cjs (esbuild) + gen_web_page.js (内嵌 HTML)
  docs/
```

## 6. 编译参数

CMake 设置 C11（严格 `-std=c11`），统一注入 `_POSIX_C_SOURCE=200809L`、`_DEFAULT_SOURCE=1`
（否则 glibc 会藏掉 `getaddrinfo`/`localtime_r` 等 POSIX 符号，`test_portability` 守着这条）。
`CMAKE_BUILD_TYPE` 由 CMake 控制（默认空 = 无优化无调试信息，建议显式 `Debug`）。

## 7. 质量与检查（Makefile 目标）

```sh
make test          # 单元测试（C + web_vitest + web_tsc）
make asan          # AddressSanitizer + UBSan（内存泄漏/越界）
make ubsan         # UndefinedBehaviorSanitizer
make tsan          # ThreadSanitizer（数据竞争）
make coverage      # gcov 覆盖率报告
make tidy          # clang-tidy 静态分析
make cppcheck      # cppcheck
make scan-build    # Clang Static Analyzer
```

Sanitizer 对 C 项目非常有用：可捕获越界、use-after-free、内存泄漏、整数溢出、数据竞争等，建议 Debug/CI 默认开启 ASan+UBSan。

## 8. 测试清单

C 单测：`test_smoke / test_config / test_router / test_auth / test_socks5 / test_http_proxy /
test_stats / test_db / test_upstream_probe / test_web_api / test_geo / test_portability /
test_strutil / test_pidfile / test_daemon / test_startup_info / test_dns / test_web_page`，
外加前端 `web_vitest`（vitest + happy-dom）与 `web_tsc`（`tsc --noEmit`）。
后两项需要全局 `vitest` / `happy-dom` / `tsc`，缺失时 configure 阶段静默跳过。

权威清单是 `tests/CMakeLists.txt`（`ctest --test-dir build -N` 可列），本文件不做计数。
