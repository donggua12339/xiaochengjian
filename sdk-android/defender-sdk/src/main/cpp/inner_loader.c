/**
 * inner_loader.c - 小城笺加固 v0.1: inner .so 内存加载器
 *
 * 在 .init_array 阶段执行(早于 JNI_OnLoad,早于所有 Java 代码和 hook 框架):
 *  1. 从 .rodata 读取加密的 inner .so 数据
 *  2. XOR 解密到堆内存
 *  3. memfd_create 创建匿名文件描述符
 *  4. write 解密后的 .so 到匿名 fd
 *  5. dlopen("/proc/self/fd/N") 从匿名 fd 加载
 *  6. dlsym 获取 inner 函数指针
 *  7. 清除堆内存中的解密数据(防 dump)
 *
 * 对抗效果:
 *  - inner .so 不落盘,SRPatch/MT 无法提取
 *  - 加载路径 /proc/self/fd/N,路径重定向无法匹配
 *  - 加密数据在 .rodata,静态分析只看到密文
 *  - 解密后立即清零,缩小 dump 窗口
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <android/log.h>
#include "custom_linker.h"

#define TAG "DefenderInnerLoader"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ============= 加密 inner .so 数据(由 build_inner_so.py 生成) ============= */

/* 占位:编译时由 build_inner_so.py 替换为真实加密数据 */
#include "inner_defender_enc.h"

/* ============= XOR 解密 ============= */

static void xor_decrypt(uint8_t *data, size_t len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

/* ============= inner 函数指针 ============= */

typedef uint32_t (*fn_inner_get_version)(void);
typedef int (*fn_inner_verify_hash)(const char *, const char *);
typedef int (*fn_inner_env_check)(const char *, int);
typedef int (*fn_inner_self_check)(const void *, uint32_t, uint32_t);

static fn_inner_get_version g_inner_version = NULL;
static fn_inner_verify_hash g_inner_verify_hash = NULL;
static fn_inner_env_check g_inner_env_check = NULL;
static fn_inner_self_check g_inner_self_check = NULL;
static cl_handle_t g_inner_handle = NULL;  /* 自实现 Linker 句柄 */

/* ============= 加载流程(自实现 Linker) ============= */

/**
 * 加载 inner .so — 使用自实现 Linker(v0.2)
 *
 * 完全不依赖系统 dlopen/dlsym:
 *  1. XOR 解密 inner .so 到堆内存
 *  2. cl_dlopen_mem 从内存加载(自实现 ELF 解析 + 段映射 + 重定位)
 *  3. cl_call_constructors 调用 .init/.init_array
 *  4. cl_dlsym 获取导出函数指针
 *  5. 清零解密数据
 *
 * 对抗效果:
 *  - 不走系统 Linker → PLT/GOT hook 全部失效
 *  - 匿名 mmap 映射 → /proc/self/maps 无 .so 文件名
 *  - 不 open 文件 → SRPatch 的 openat hook 拦截不到
 *
 * @return 0=成功 / -1=失败
 */
static int inner_loader_load(void) {
    LOGI("inner_loader: 开始加载 inner .so (size=%d, 自实现 Linker)", INNER_ENC_SIZE);

    /* 1. 复制加密数据到堆(不修改 .rodata) */
    uint8_t *decrypted = (uint8_t *)malloc(INNER_ENC_SIZE);
    if (!decrypted) {
        LOGE("inner_loader: malloc 失败");
        return -1;
    }
    memcpy(decrypted, INNER_ENC_DATA, INNER_ENC_SIZE);

    /* 2. XOR 解密 */
    xor_decrypt(decrypted, INNER_ENC_SIZE, INNER_ENC_KEY, INNER_ENC_KEY_LEN);

    /* 验证 ELF magic */
    if (decrypted[0] != 0x7f || decrypted[1] != 'E' ||
        decrypted[2] != 'L' || decrypted[3] != 'F') {
        LOGE("inner_loader: 解密后非 ELF(magic=0x%02x%02x%02x%02x)",
             decrypted[0], decrypted[1], decrypted[2], decrypted[3]);
        memset(decrypted, 0, INNER_ENC_SIZE);
        free(decrypted);
        return -1;
    }
    LOGI("inner_loader: ELF magic 验证通过");

    /* 3. 自实现 Linker 从内存加载(不走系统 dlopen) */
    g_inner_handle = cl_dlopen_mem(decrypted, INNER_ENC_SIZE, "inner_defender");
    if (!g_inner_handle) {
        LOGE("inner_loader: cl_dlopen_mem 失败");
        memset(decrypted, 0, INNER_ENC_SIZE);
        free(decrypted);
        return -1;
    }
    LOGI("inner_loader: cl_dlopen_mem 成功 base=0x%lx size=%zu",
         (unsigned long)cl_get_base(g_inner_handle), cl_get_size(g_inner_handle));

    /* 4. 调用构造函数 */
    cl_call_constructors(g_inner_handle);

    /* 5. 立即清零解密数据(缩小 dump 窗口) */
    memset(decrypted, 0, INNER_ENC_SIZE);
    free(decrypted);

    /* 6. cl_dlsym 获取函数指针(自实现符号查找,不走系统 dlsym) */
    g_inner_version = (fn_inner_get_version)cl_dlsym(g_inner_handle, "inner_get_version");
    g_inner_verify_hash = (fn_inner_verify_hash)cl_dlsym(g_inner_handle, "inner_verify_hash");
    g_inner_env_check = (fn_inner_env_check)cl_dlsym(g_inner_handle, "inner_env_check");
    g_inner_self_check = (fn_inner_self_check)cl_dlsym(g_inner_handle, "inner_self_check");

    if (!g_inner_version || !g_inner_verify_hash) {
        LOGE("inner_loader: cl_dlsym 失败(version=%p verify=%p)",
             (void *)g_inner_version, (void *)g_inner_verify_hash);
        cl_dlclose(g_inner_handle);
        g_inner_handle = NULL;
        return -1;
    }

    /* 7. 验证 inner 版本 */
    uint32_t ver = g_inner_version();
    LOGI("inner_loader: inner 版本=%u.%u.%u (自实现 Linker 加载)",
         (ver >> 16) & 0xff, (ver >> 8) & 0xff, ver & 0xff);

    LOGI("inner_loader: 加载完成,4 个函数已绑定(无系统 dlopen/dlsym)");
    return 0;
}

/* ============= .init_array 构造器 ============= */

__attribute__((constructor))
static void inner_loader_init(void) {
    inner_loader_load();
}

/* ============= 供外壳调用的接口 ============= */

int inner_loader_is_loaded(void) {
    return (g_inner_handle != NULL) ? 1 : 0;
}

uint32_t inner_loader_get_version(void) {
    return g_inner_version ? g_inner_version() : 0;
}

int inner_loader_verify_hash(const char *hash_hex, const char *expected_hex) {
    return g_inner_verify_hash ? g_inner_verify_hash(hash_hex, expected_hex) : -1;
}

int inner_loader_env_check(const char *maps_content, int maps_len) {
    return g_inner_env_check ? g_inner_env_check(maps_content, maps_len) : -1;
}
