/* 可移植性回归测试。
 *
 * 背景：CI 在 Linux(glibc) 上构建失败——CMAKE_C_EXTENSIONS OFF 让编译用严格
 * -std=c11，glibc 的 features.h 在这种模式下隐藏 getaddrinfo/localtime_r，
 * 报 "storage size of 'hints' isn't known"（struct addrinfo 不完整）。
 * macOS 的头文件宽松，本地怎么编都能过，所以问题只在 CI 暴露。
 *
 * 对策是把 POSIX 特性宏（_POSIX_C_SOURCE>=200809L）从 CMakeLists 统一注入，
 * 而不是在每个 .c 里各自 #define（漏一个就是一个平台编不过）。
 * 本文件把这件事钉在编译期：宏一旦被拿掉，这个测试目标直接编译失败。
 */
#include <cmocka.h>

#include <netdb.h>
#include <string.h>
#include <time.h>

#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200809L
#error "rybaproxy 需要 _POSIX_C_SOURCE>=200809L（由 CMakeLists 统一注入），\
否则严格 -std=c11 下 glibc 会隐藏 getaddrinfo/localtime_r，Linux 构建失败"
#endif

/* 光有宏不够：真正把这些符号用一遍，声明缺失就在编译期炸出来 */
static void test_posix_symbols_declared(void **state) {
    (void)state;
    struct addrinfo hints;
    struct tm tm;
    time_t now = time(NULL);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    assert_int_equal(hints.ai_family, AF_UNSPEC);

    assert_non_null(localtime_r(&now, &tm));
    assert_int_equal(tm.tm_year >= 0, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_posix_symbols_declared),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
