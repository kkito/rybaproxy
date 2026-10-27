/* 大小写不敏感的子串查找，替代 glibc 的 GNU 扩展 strcasestr（不可移植）。
 * 纯函数：无状态、无分配，语义与 strstr 一致（返回 haystack 内指针）。 */
#ifndef RYBAPROXY_STRUTIL_H
#define RYBAPROXY_STRUTIL_H

#include <stddef.h>

const char *str_case_find(const char *haystack, const char *needle);

#endif
