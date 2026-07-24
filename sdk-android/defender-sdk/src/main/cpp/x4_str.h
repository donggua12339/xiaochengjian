/**
 * x4_str.h - X4-0 基建:自实现字符串/内存函数(ADR 0093)
 *
 * 不依赖 libc 的 strstr/strcmp/strlen——攻击者"一把梭"hook libc 字符串函数
 * (凡 args[1] 含关键词即改返回值 0)对自实现无效(调研 看雪4 结论)。
 * 逐字节实现;关键检测处配合 X1 OBF 密文 + svc 直读使用。
 */
#ifndef X4_STR_H
#define X4_STR_H

#include <stddef.h>

size_t x4_strlen(const char *s);
int    x4_strcmp(const char *a, const char *b);
int    x4_strncmp(const char *a, const char *b, size_t n);
char  *x4_strstr(const char *haystack, const char *needle);
int    x4_memcmp(const void *a, const void *b, size_t n);
void  *x4_memset(void *s, int c, size_t n);

#endif /* X4_STR_H */
