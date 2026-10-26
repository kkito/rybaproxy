# 构建与依赖

## 1. 依赖管理：vcpkg

本项目使用 **vcpkg manifest 模式**（`vcpkg.json`）管理 C 依赖，重复利用本机 vcpkg（默认 `~/vcpkg`）。

依赖：
- libevent（core/extra/pthreads）
- OpenSSL
- SQLite3
- cJSON
- cmocka（测试）

## 2. 构建步骤

```sh
# 1) 安装 vcpkg（若未安装）
git clone https://github.com/microsoft/vcpkg.git ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh

# 2) 安装依赖（manifest 模式）
cd rybaproxy
~/vcpkg/vcpkg install

# 3) 配置 & 构建
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=$HOME/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build

# 4) 运行测试
ctest --test-dir build
```

## 3. 目录

```
rybaproxy/
  CMakeLists.txt
  vcpkg.json
  src/
  tests/
  include/
  web/static/
  scripts/
  docs/
```

## 4. 编译参数

CMake 设置 C11，开启 `-Wall -Wextra -Wpedantic`（可在 CMakeLists 调整）。默认 Debug/RelWithDebInfo 由 CMake 控制。

## 5. 嵌入静态资源

`scripts/embed_static.py` 将 `web/static/` 生成 `src/web/static_gen.c`。开发模式 `-DDEV_WEB_ROOT=...` 从磁盘读取。

## 6. 质量与检查（Makefile 目标）

```sh
make test          # 单元测试
make asan          # AddressSanitizer + UBSan（内存泄漏/越界）
make ubsan         # UndefinedBehaviorSanitizer
make tsan          # ThreadSanitizer（数据竞争）
make coverage      # gcov 覆盖率报告
make tidy          # clang-tidy 静态分析
make cppcheck      # cppcheck
make scan-build    # Clang Static Analyzer
```

Sanitizer 对 C 项目非常有用：可捕获越界、use-after-free、内存泄漏、整数溢出、数据竞争等，建议 Debug/CI 默认开启 ASan+UBSan。
