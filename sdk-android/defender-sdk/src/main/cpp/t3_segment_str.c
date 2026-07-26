/**
 * t3_segment_str.c - T3 字符串分段散列存储+运行时组装+用后清零(天衍)
 *
 * 对抗:内存 dump 后只能拿到分散片段,无法直接还原完整字符串。
 *
 * 架构:
 *   构建期: 字符串拆 2-4 段,每段 XOR 加密后存入不同数组(不同 section)
 *   运行时: t3_assemble(index) → 从各段数组取片段 → 拼接 → XOR 解密 → 返回
 *           调用方用完后必须调 t3_wipe(buf, len) 清零
 *
 * 与 T2 的协同: T2 保护解密函数(VMP),T3 保护存储形式(分段散列)。
 * 即使 hook 了解密函数,内存中也不存在完整的加密字符串(只有片段)。
 */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define DEFENDER_TAG "T3Segment"
#include "defender_log.h"

#ifdef T4_ENABLED
#include "t4_str_key.h"
#include "vm_engine.h"
#include "vm_bytecode.h"

/* 最大分段数 */
#define T3_MAX_SEGMENTS 4
/* 最大字符串长度 */
#define T3_MAX_STR_LEN 512

/**
 * 分段描述符(构建期生成,存入 .rodata)
 * 每个字符串一条记录:segment_count + 各段的 offset/len
 */
typedef struct {
    uint8_t seg_count;                    /* 分段数(2-4) */
    uint16_t seg_offsets[T3_MAX_SEGMENTS]; /* 各段在段池中的偏移 */
    uint16_t seg_lengths[T3_MAX_SEGMENTS]; /* 各段长度 */
} t3_descriptor_t;

/* 段池:所有加密片段连续存储(构建期生成)
 * 实际项目中应分散到不同 section;此处 MVP 用单池 + 运行时散列访问 */
extern const uint8_t T3_SEG_POOL[];
extern const uint32_t T3_SEG_POOL_SIZE;
extern const t3_descriptor_t T3_DESCRIPTORS[];
extern const uint32_t T3_DESCRIPTOR_COUNT;

/**
 * 组装并解密第 index 个字符串。
 *
 * @param index 字符串索引
 * @param out_buf 输出缓冲(调用方提供,≥T3_MAX_STR_LEN)
 * @param out_len 输出实际长度
 * @return 0=成功 / -1=失败
 */
int t3_assemble(uint32_t index, char *out_buf, uint32_t *out_len) {
    if (index >= T3_DESCRIPTOR_COUNT) return -1;

    const t3_descriptor_t *desc = &T3_DESCRIPTORS[index];
    uint32_t total_len = 0;

    /* 1. 从各段取片段,拼接到 out_buf */
    for (uint8_t i = 0; i < desc->seg_count; i++) {
        uint16_t off = desc->seg_offsets[i];
        uint16_t len = desc->seg_lengths[i];
        if (off + len > T3_SEG_POOL_SIZE) return -1;
        if (total_len + len > T3_MAX_STR_LEN) return -1;
        memcpy(out_buf + total_len, T3_SEG_POOL + off, len);
        total_len += len;
    }

    /* 2. VMP XOR 解密(复用 T2 的 VM 字节码) */
    vm_context_t vm;
    vm_init(&vm, VM_BC_xor_decrypt, VM_BC_xor_decrypt_size);
    vm_set_arg(&vm, 0, (uint64_t)(uintptr_t)out_buf);
    vm_set_arg(&vm, 1, (uint64_t)(uintptr_t)T4_XOR_KEY);
    vm_set_arg(&vm, 2, (uint64_t)total_len);
    vm_set_arg(&vm, 3, (uint64_t)T4_XOR_KEY_LEN);
    vm_execute(&vm);

    *out_len = total_len;
    return 0;
}

/**
 * 用后清零(防内存残留)。
 * 调用方获取字符串并使用完毕后必须调用。
 */
void t3_wipe(char *buf, uint32_t len) {
    if (buf && len > 0) {
        memset(buf, 0, len);
    }
}

#else /* T4_ENABLED not defined */

int t3_assemble(uint32_t index, char *out_buf, uint32_t *out_len) {
    (void)index; (void)out_buf; (void)out_len;
    return -1;
}
void t3_wipe(char *buf, uint32_t len) {
    (void)buf; (void)len;
}

#endif /* T4_ENABLED */
