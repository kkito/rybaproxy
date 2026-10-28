cmake_minimum_required(VERSION 3.20)
project(rybaproxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# 严格 -std=c11 下 glibc 的 features.h 会隐藏 getaddrinfo/localtime_r 等 POSIX
# 符号（struct addrinfo 直接不完整）；macOS 头文件宽松所以本地编得过、CI 编不过。
# 统一在这里注入，避免每个 .c 各自 #define 漏一个就挂一个平台。
# 由 test_portability 的编译期 #error 守着，宏被拿掉会立刻红。
add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE=1)

option(RYBA_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(RYBA_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(RYBA_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(RYBA_ENABLE_COVERAGE "Enable code coverage (gcov)" OFF)

option(RYBA_BUILD_TESTS "Build tests" ON)
option(RYBA_USE_VCPKG "Use vcpkg toolchain" ON)
find_program(RYBA_NODE_EXECUTABLE node REQUIRED)
# Web 页面没有“旧东西”：唯一来源 web/src/*.ts + web/index.html + web/style.css
# 每次构建必经：scripts/build_web.cjs (esbuild, global) → build/web-dist/ryba-web.js
# → scripts/gen_web_page.js → build/generated/web_page_gen.h (WEB_PAGE_HTML_GEN)
# 输出只落 build/，不写回源码树。node 缺失直接配不过，不静默降级。
# global esbuild needs NODE_PATH to resolve (no local node_modules)
if(NOT RYBA_GLOBAL_NODE_PATH)
    find_program(RYBA_NPM_EXECUTABLE npm)
    if(RYBA_NPM_EXECUTABLE)
        execute_process(COMMAND "${RYBA_NPM_EXECUTABLE}" root -g
            OUTPUT_VARIABLE RYBA_GLOBAL_NODE_PATH OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    endif()
endif()
set(RYBA_WEB_DIST_DIR "${CMAKE_CURRENT_BINARY_DIR}/web-dist")
set(RYBA_WEB_GEN_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated/web_page_gen.h")
file(GLOB RYBA_WEB_SRCS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/web/src/*.ts")
add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/ryba_web_page.stamp" "${RYBA_WEB_GEN_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E env "NODE_PATH=${RYBA_GLOBAL_NODE_PATH}" "${RYBA_NODE_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/build_web.cjs" "${RYBA_WEB_DIST_DIR}"
    COMMAND "${RYBA_NODE_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_web_page.js" "${RYBA_WEB_DIST_DIR}" "${RYBA_WEB_GEN_HEADER}"
    COMMAND "${CMAKE_COMMAND}" -E touch "${CMAKE_CURRENT_BINARY_DIR}/ryba_web_page.stamp"
    DEPENDS ${RYBA_WEB_SRCS}
            "${CMAKE_CURRENT_SOURCE_DIR}/web/index.html"
            "${CMAKE_CURRENT_SOURCE_DIR}/web/style.css"
            "${CMAKE_CURRENT_SOURCE_DIR}/scripts/build_web.cjs"
            "${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_web_page.js"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Building web UI (esbuild + gen_web_page)"
    VERBATIM)
add_custom_target(ryba_web_page DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/ryba_web_page.stamp")

# Global sanitizers/coverage
if(RYBA_ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()
if(RYBA_ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined)
endif()
if(RYBA_ENABLE_TSAN)
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
endif()
if(RYBA_ENABLE_COVERAGE)
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif()

# ---- 版本号：VERSION 文件为准，git describe 补 commit/构建时间 ----
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" RYBA_VERSION_RAW)
string(STRIP "${RYBA_VERSION_RAW}" RYBA_VERSION)

find_program(RYBA_GIT_EXECUTABLE git)
set(RYBA_GIT_COMMIT "unknown")
set(RYBA_VERSION_FULL "${RYBA_VERSION}")
if(RYBA_GIT_EXECUTABLE)
    execute_process(
        COMMAND "${RYBA_GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}" rev-parse --short HEAD
        OUTPUT_VARIABLE RYBA_GIT_COMMIT_OUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE RYBA_GIT_RC)
    if(RYBA_GIT_RC EQUAL 0 AND RYBA_GIT_COMMIT_OUT)
        set(RYBA_GIT_COMMIT "${RYBA_GIT_COMMIT_OUT}")
    endif()
    execute_process(
        COMMAND "${RYBA_GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}" describe --tags --dirty --always
        OUTPUT_VARIABLE RYBA_DESCRIBE_OUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE RYBA_DESCRIBE_RC)
    if(RYBA_DESCRIBE_RC EQUAL 0 AND RYBA_DESCRIBE_OUT)
        set(RYBA_VERSION_FULL "${RYBA_DESCRIBE_OUT}")
    endif()
endif()
string(TIMESTAMP RYBA_BUILD_TIME "%Y-%m-%dT%H:%M:%S" UTC)
message(STATUS "rybaproxy version: ${RYBA_VERSION_FULL} (commit ${RYBA_GIT_COMMIT})")

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/rybaproxy/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/rybaproxy/version.h"
    @ONLY)

find_package(PkgConfig QUIET)
# Dependencies via vcpkg
find_package(Libevent CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(cJSON CONFIG REQUIRED)
find_package(CivetWeb CONFIG REQUIRED)
find_package(llhttp CONFIG REQUIRED)
find_package(c-ares CONFIG REQUIRED)

file(GLOB_RECURSE RYBA_SRCS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
list(FILTER RYBA_SRCS EXCLUDE REGEX "/tests/")
# separate main
set(RYBA_MAIN "")
foreach(f ${RYBA_SRCS})
    if(f MATCHES ".*/main\.c$")
        set(RYBA_MAIN ${f})
        list(REMOVE_ITEM RYBA_SRCS ${f})
    endif()
endforeach()

add_library(rybaproxy_core STATIC ${RYBA_SRCS})

# ---- Frontend tests (vitest + tsc, global toolchain, no local node_modules) ----
if(RYBA_BUILD_TESTS AND RYBA_NODE_EXECUTABLE)
    find_program(RYBA_VITEST_EXECUTABLE vitest)
    if(RYBA_VITEST_EXECUTABLE AND RYBA_GLOBAL_NODE_PATH)
        # NODE_PATH lets vitest resolve global happy-dom without local install
        add_test(NAME web_vitest
            COMMAND ${CMAKE_COMMAND} -E env "NODE_PATH=${RYBA_GLOBAL_NODE_PATH}"
                "${RYBA_VITEST_EXECUTABLE}" run
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/web")
    endif()
    find_program(RYBA_TSC_EXECUTABLE tsc)
    if(RYBA_TSC_EXECUTABLE)
        add_test(NAME web_tsc
            COMMAND "${RYBA_TSC_EXECUTABLE}" --noEmit -p tsconfig.json
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/web")
    endif()
endif()
target_include_directories(rybaproxy_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}/generated
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
# web_page_gen.h 是构建产物（build/generated/），必须依赖生成 target
add_dependencies(rybaproxy_core ryba_web_page)
target_link_libraries(rybaproxy_core PUBLIC
    libevent::core libevent::extra libevent::pthreads
    OpenSSL::SSL OpenSSL::Crypto
    unofficial::sqlite3::sqlite3
    cjson
    civetweb::civetweb
    llhttp::llhttp_static
    c-ares::cares)

add_executable(rybaproxy ${RYBA_MAIN})
target_link_libraries(rybaproxy PRIVATE rybaproxy_core)

# Sanitizers
if(RYBA_ENABLE_ASAN)
    target_compile_options(rybaproxy_core PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(rybaproxy_core PRIVATE -fsanitize=address)
endif()
if(RYBA_ENABLE_UBSAN)
    target_compile_options(rybaproxy_core PRIVATE -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(rybaproxy_core PRIVATE -fsanitize=undefined)
endif()
if(RYBA_ENABLE_TSAN)
    target_compile_options(rybaproxy_core PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
    target_link_options(rybaproxy_core PRIVATE -fsanitize=thread)
endif()
if(RYBA_ENABLE_COVERAGE)
    target_compile_options(rybaproxy_core PRIVATE --coverage -O0 -g)
    target_link_options(rybaproxy_core PRIVATE --coverage)
endif()
if(RYBA_ENABLE_ASAN)
    target_compile_options(rybaproxy PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(rybaproxy PRIVATE -fsanitize=address)
endif()
if(RYBA_ENABLE_UBSAN)
    target_compile_options(rybaproxy PRIVATE -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(rybaproxy PRIVATE -fsanitize=undefined)
endif()
if(RYBA_ENABLE_TSAN)
    target_compile_options(rybaproxy PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
    target_link_options(rybaproxy PRIVATE -fsanitize=thread)
endif()
if(RYBA_ENABLE_COVERAGE)
    target_compile_options(rybaproxy PRIVATE --coverage -O0 -g)
    target_link_options(rybaproxy PRIVATE --coverage)
endif()

if(RYBA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
