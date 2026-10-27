#include "rybaproxy/strutil.h"

/* ASCII 大小写折叠（纯函数）：避免 locale 相关的 tolower 行为差异 */
static char fold(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

const char *str_case_find(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    size_t nlen = 0;
    while (needle[nlen]) nlen++;
    if (nlen == 0) return haystack;            /* 与 strstr 语义一致 */
    for (const char *h = haystack; *h; h++) {
        size_t i = 0;
        while (i < nlen && h[i] && fold(h[i]) == fold(needle[i])) i++;
        if (i == nlen) return h;
    }
    return NULL;
}
