/**
 * xcj_loader.c - X0-3「stub loader」原型(不加密的小 .so,正常 System.loadLibrary 加载)
 *
 * 自举链(X0 最难的核心):
 *   1. 读嵌入 .rodata 的加密载荷(x0test_enc.h,RC4 + 魔数框架)
 *   2. so_cipher_extract 解密(明文只在 native 堆)
 *   3. 验 ELF magic
 *   4. memfd_create + write → android_dlopen_ext(ANDROID_DLEXT_USE_LIBRARY_FD) 内存加载
 *   5. dlsym 出载荷的 JNI_OnLoad 并**手动调用**(android_dlopen_ext 不会自动调它)
 *      → 载荷注册 native,Java 即可调用
 *   6. memset 清零解密缓冲(缩小 dump 窗口)
 *
 * 原型载荷是 x0test(注册 DefenderX0Test.ping);跑通后换成真外壳 libxcj_defender.so。
 * 硬约束(见 ADR 0092 §2):必须 memfd(不明文落地);JNI_OnLoad 须手动调。
 */
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <android/log.h>
#include <android/dlext.h>

#include "so_cipher.h"
#include "x0test_enc.h"   /* X0TEST_ENC_DATA / SIZE / KEY(build_x0test.py 生成) */

#define TAG "XcjLoader"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static JavaVM *g_vm = NULL;

/* memfd_create:minSdk 24 无 libc 包装,走 syscall */
static int xcj_memfd(const char *name, unsigned int flags) {
#if defined(__aarch64__)
    return (int)syscall(279, name, flags);   /* __NR_memfd_create arm64 */
#elif defined(__arm__)
    return (int)syscall(385, name, flags);   /* __NR_memfd_create arm */
#else
    return memfd_create(name, flags);
#endif
}

/* 从内存加载 .so:memfd 写入 + android_dlopen_ext(USE_LIBRARY_FD) */
static void *load_so_from_mem(const uint8_t *so, size_t len, const char *name) {
    int fd = xcj_memfd(name, 0);
    if (fd < 0) { LOGE("memfd_create 失败"); return NULL; }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, so + off, len - off);
        if (w <= 0) { LOGE("write memfd 失败"); close(fd); return NULL; }
        off += (size_t)w;
    }
    android_dlextinfo ext;
    memset(&ext, 0, sizeof(ext));
    ext.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    ext.library_fd = fd;
    void *handle = android_dlopen_ext(name, RTLD_NOW, &ext);
    close(fd);   /* 映射已建立,可关 fd */
    return handle;
}

static int bootstrap_payload(void) {
    LOGI("X0 原型:加载加密载荷(框架 %d 字节)", X0TEST_ENC_SIZE);

    /* 1. RC4 解密(so_cipher 尾部魔数框架) */
    uint8_t *plain = (uint8_t *)malloc(X0TEST_ENC_SIZE);
    if (!plain) { LOGE("malloc 失败"); return -1; }
    uint32_t plain_len = 0;
    if (so_cipher_extract(X0TEST_ENC_DATA, X0TEST_ENC_SIZE,
                          X0TEST_ENC_KEY, X0TEST_ENC_KEY_LEN,
                          plain, &plain_len) != 0) {
        LOGE("so_cipher_extract 失败(魔数/长度异常)");
        free(plain);
        return -1;
    }
    LOGI("解密成功 plain_len=%u", plain_len);

    /* 2. 验 ELF magic */
    if (plain_len < 4 || plain[0] != 0x7f || plain[1] != 'E' ||
        plain[2] != 'L' || plain[3] != 'F') {
        LOGE("解密后非 ELF");
        memset(plain, 0, plain_len); free(plain);
        return -1;
    }

    /* 3. memfd + android_dlopen_ext */
    void *handle = load_so_from_mem(plain, plain_len, "libx0test.so");

    /* 4. 立即清理解密缓冲 */
    memset(plain, 0, plain_len);
    free(plain);

    if (!handle) { LOGE("android_dlopen_ext 失败:%s", dlerror()); return -1; }
    LOGI("android_dlopen_ext 成功 handle=%p", handle);

    /* 5. 手动调载荷的 JNI_OnLoad(注册 native) */
    typedef jint (*jni_onload_t)(JavaVM *, void *);
    jni_onload_t on_load = (jni_onload_t)dlsym(handle, "JNI_OnLoad");
    if (!on_load) { LOGE("dlsym JNI_OnLoad 失败"); return -1; }
    jint rc = on_load(g_vm, NULL);
    LOGI("载荷 JNI_OnLoad 返回 %d", rc);
    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    LOGI("xcj_loader: JNI_OnLoad,开始自举载荷");
    if (bootstrap_payload() != 0) {
        LOGE("xcj_loader: 载荷自举失败(仍返回版本,避免 stub 被卸载)");
    }
    return JNI_VERSION_1_6;
}
