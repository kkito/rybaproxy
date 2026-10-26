# Makefile wrapper for rybaproxy (CMake + vcpkg)

VCPKG_ROOT ?= $(HOME)/vcpkg
CLANG_TIDY ?= $(shell command -v clang-tidy 2>/dev/null || echo /opt/homebrew/opt/llvm/bin/clang-tidy)
SCAN_BUILD ?= $(shell command -v scan-build 2>/dev/null || echo /opt/homebrew/opt/llvm/bin/scan-build)
CPPCHECK ?= $(shell command -v cppcheck 2>/dev/null || echo cppcheck)
TOOLCHAIN  := $(VCPKG_ROOT)/scripts/buildsystems/vcpkg.cmake
BUILD_DIR  ?= build
CMAKE      ?= cmake
CTEST      ?= ctest
JOBS       ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

CMAKE_COMMON := -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
                -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

.PHONY: all configure build test clean \
        asan ubsan tsan coverage \
        tidy cppcheck scan-build help

all: build

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) $(CMAKE_COMMON) -DCMAKE_BUILD_TYPE=Debug

build: configure
	$(CMAKE) --build $(BUILD_DIR) -j$(JOBS)

test: build
	$(CTEST) --test-dir $(BUILD_DIR) --output-on-failure

# Sanitizers
asan:
	rm -rf build-asan
	$(CMAKE) -S . -B build-asan $(CMAKE_COMMON) \
	  -DRYBA_ENABLE_ASAN=ON -DRYBA_ENABLE_UBSAN=ON -DCMAKE_BUILD_TYPE=Debug
	$(CMAKE) --build build-asan -j$(JOBS)
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 $(CTEST) --test-dir build-asan --output-on-failure

ubsan:
	rm -rf build-ubsan
	$(CMAKE) -S . -B build-ubsan $(CMAKE_COMMON) \
	  -DRYBA_ENABLE_UBSAN=ON -DCMAKE_BUILD_TYPE=Debug
	$(CMAKE) --build build-ubsan -j$(JOBS)
	UBSAN_OPTIONS=print_stacktrace=1 $(CTEST) --test-dir build-ubsan --output-on-failure

tsan:
	rm -rf build-tsan
	$(CMAKE) -S . -B build-tsan $(CMAKE_COMMON) \
	  -DRYBA_ENABLE_TSAN=ON -DCMAKE_BUILD_TYPE=Debug
	$(CMAKE) --build build-tsan -j$(JOBS)
	TSAN_OPTIONS=halt_on_error=1 $(CTEST) --test-dir build-tsan --output-on-failure

coverage:
	rm -rf build-cov
	$(CMAKE) -S . -B build-cov $(CMAKE_COMMON) \
	  -DRYBA_ENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug
	$(CMAKE) --build build-cov -j$(JOBS)
	$(CTEST) --test-dir build-cov --output-on-failure
	@command -v lcov >/dev/null 2>&1 && lcov --capture --directory build-cov --output-file build-cov/coverage.info && \
	  (command -v genhtml >/dev/null 2>&1 && genhtml build-cov/coverage.info --output-directory build-cov/coverage-report) || true
	@echo "Coverage data: build-cov/coverage.info"

# Static analysis
tidy: configure
	@test -x "$(CLANG_TIDY)" || { echo "clang-tidy not found: $(CLANG_TIDY)"; exit 1; }
	$(CLANG_TIDY) -p $(BUILD_DIR) $(shell find src include -type f \( -name '*.c' -o -name '*.h' \))

cppcheck:
	@command -v cppcheck >/dev/null 2>&1 || { echo "cppcheck not found (brew install cppcheck)"; exit 1; }
	$(CPPCHECK) --enable=all --inconclusive --std=c11 --quiet \
	  -I include -I $(VCPKG_ROOT)/installed/arm64-osx/include src

scan-build:
	@test -x "$(SCAN_BUILD)" || { echo "scan-build not found: $(SCAN_BUILD)"; exit 1; }
	rm -rf build-scan
	$(SCAN_BUILD) $(CMAKE) -S . -B build-scan $(CMAKE_COMMON) -DCMAKE_BUILD_TYPE=Debug
	$(SCAN_BUILD) $(CMAKE) --build build-scan -j$(JOBS)

clean:
	rm -rf build build-* compile_commands.json

help:
	@echo "Targets: all build test asan ubsan tsan coverage tidy cppcheck scan-build clean"
