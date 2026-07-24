/**
 * x4_str.c - 自实现字符串/内存函数(X4-0)
 *
 * 逐字节实现,不调用任何 libc 字符串函数,使 hook libc strstr/strcmp 的绕过失效。
 * 实现求简求正确;抗逆向强度由调用处的 X1 OBF 密文 + 检测分散提供。
 */
#include "x4_str.h"

size_t x4_strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

int x4_strcmp(const char *a, const char *b) {
    while (*a && (unsigned char)*a == (unsigned char)*b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int x4_strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && (unsigned char)*a == (unsigned char)*b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

char *x4_strstr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    for (; *haystack; haystack++) {
        if (*haystack == *needle) {
            const char *h = haystack, *nd = needle;
            while (*h && *nd && *h == *nd) { h++; nd++; }
            if (!*nd) return (char *)haystack;
        }
    }
    return (char *)0;
}

int x4_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;
    while (n--) {
        if (*x != *y) return (int)*x - (int)*y;
        x++; y++;
    }
    return 0;
}

void *x4_memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}
