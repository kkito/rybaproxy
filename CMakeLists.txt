cmake_minimum_required(VERSION 3.20)
project(rybaproxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(RYBA_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(RYBA_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(RYBA_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(RYBA_ENABLE_COVERAGE "Enable code coverage (gcov)" OFF)

option(RYBA_BUILD_TESTS "Build tests" ON)
option(RYBA_USE_VCPKG "Use vcpkg toolchain" ON)

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
target_include_directories(rybaproxy_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
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
