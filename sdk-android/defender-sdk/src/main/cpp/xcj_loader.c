/**
 * xcj_loader.c - X0-3「stub loader」(不加密的小 .so,正常 System.loadLibrary 加载)
 *
 * 自举链(X0 最难的核心,ADR 0092 §2):
 *   Java 调 bootstrap(apkPath) →
 *   1. mmap APK,扫 XCJSO1 魔数框架定位密文(支持 (i) 资源尾/(ii) 专用 asset,STORED)
 *   2. so_cipher_extract 解密(明文只在 native 堆)
 *   3. 验 ELF magic
 *   4. memfd_create + write → android_dlopen_ext(ANDROID_DLEXT_USE_LIBRARY_FD)
 *   5. dlsym 出载荷 JNI_OnLoad 并**手动调用**(android_dlopen_ext 不会自动调)→ 注册 native
 *   6. memset 清零解密缓冲 + munmap APK
 *
 * 原型载荷 = x0test(注册 DefenderX0Test.ping);跑通后换真外壳 libxcj_defender.so。
 * stub 只编译进密钥(x0_key.h),载荷密文在 APK 里(由构建/Packer 嵌入)。
 */
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <android/log.h>
#include <android/dlext.h>

#include "so_cipher.h"
#include "x0_key.h"   /* X0_KEY / X0_KEY_LEN(build_x0test.py 生成) */

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

/**
 * 在 mmap 的 APK 中扫 XCJSO1 魔数框架 → 解密 → 验 ELF。
 * 成功返回解密后的 .so(调用方负责 free),*out_len 为长度;失败返回 NULL。
 * 框架布局 [密文 len 字节][MAGIC 6][len u32 LE];MAGIC 命中点 i,密文在 [i-len, i)。
 */
static uint8_t *locate_and_decrypt(const uint8_t *apk, size_t size, uint32_t *out_len) {
    const uint8_t *magic = (const uint8_t *)SO_CIPHER_MAGIC;   /* "XCJSO1" */
    if (size < SO_CIPHER_TAILER_LEN) return NULL;
    for (size_t i = 0; i + SO_CIPHER_TAILER_LEN <= size; i++) {
        if (apk[i] != magic[0]) continue;
        if (memcmp(apk + i, magic, SO_CIPHER_MAGIC_LEN) != 0) continue;
        uint32_t len = (uint32_t)apk[i + 6] | ((uint32_t)apk[i + 7] << 8) |
                       ((uint32_t)apk[i + 8] << 16) | ((uint32_t)apk[i + 9] << 24);
        if (len == 0 || len > size) continue;
        if (i < (size_t)len) continue;               /* 密文起点 i-len 不能为负 */
        const uint8_t *frame_buf = apk + i - len;     /* [密文][MAGIC][len] */
        size_t frame_size = (size_t)len + SO_CIPHER_TAILER_LEN;
        uint8_t *plain = (uint8_t *)malloc(len);
        if (!plain) return NULL;
        uint32_t plen = 0;
        if (so_cipher_extract(frame_buf, frame_size, X0_KEY, X0_KEY_LEN,
                              plain, &plen) != 0) {
            free(plain);
            continue;                                 /* 假魔数,继续扫 */
        }
        if (plen >= 4 && plain[0] == 0x7f && plain[1] == 'E' &&
            plain[2] == 'L' && plain[3] == 'F') {
            *out_len = plen;
            return plain;                             /* 命中并解密成功 */
        }
        memset(plain, 0, plen);
        free(plain);                                  /* 解出非 ELF,假命中 */
    }
    return NULL;
}

static int bootstrap(const char *apk_path) {
    LOGI("X0 bootstrap:apk=%s", apk_path);
    int fd = open(apk_path, O_RDONLY);
    if (fd < 0) { LOGE("open apk 失败"); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0) { LOGE("fstat 失败"); close(fd); return -1; }
    size_t size = (size_t)st.st_size;
    uint8_t *apk = (uint8_t *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (apk == MAP_FAILED) { LOGE("mmap apk 失败"); return -1; }

    uint32_t so_len = 0;
    uint8_t *so = locate_and_decrypt(apk, size, &so_len);
    munmap(apk, size);                                /* 释放 APK 映射 */
    if (!so) { LOGE("未在 APK 中定位到加密载荷"); return -1; }
    LOGI("定位+解密载荷成功 len=%u", so_len);

    void *handle = load_so_from_mem(so, so_len, "libxcj_payload.so");
    memset(so, 0, so_len);                            /* 清理解密缓冲 */
    free(so);
    if (!handle) { LOGE("android_dlopen_ext 失败:%s", dlerror()); return -1; }
    LOGI("android_dlopen_ext 成功 handle=%p", handle);

    typedef jint (*jni_onload_t)(JavaVM *, void *);
    jni_onload_t on_load = (jni_onload_t)dlsym(handle, "JNI_OnLoad");
    if (!on_load) { LOGE("dlsym JNI_OnLoad 失败"); return -1; }
    jint rc = on_load(g_vm, NULL);                    /* 手动注册载荷 native */
    LOGI("载荷 JNI_OnLoad 返回 %d", rc);
    return 0;
}

/* JNI:bootstrap(apkPath) -> int(0=成功) */
static jint native_bootstrap(JNIEnv *env, jclass clazz, jstring apk_path_j) {
    (void)clazz;
    const char *apk_path = apk_path_j ? (*env)->GetStringUTFChars(env, apk_path_j, NULL) : NULL;
    if (!apk_path) return -1;
    int rc = bootstrap(apk_path);
    (*env)->ReleaseStringUTFChars(env, apk_path_j, apk_path);
    return rc;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    LOGI("xcj_loader: JNI_OnLoad,注册 bootstrap");
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass clazz = (*env)->FindClass(env, "com/xcj/defender/DefenderX0Test");
    if (clazz == NULL) {
        LOGE("FindClass DefenderX0Test 失败");
        return JNI_VERSION_1_6;
    }
    /* 只注册 bootstrap;ping 由载荷(x0test)的 JNI_OnLoad 注册 */
    JNINativeMethod methods[] = {
        {"bootstrap", "(Ljava/lang/String;)I", (void *)native_bootstrap},
    };
    jint rc = (*env)->RegisterNatives(env, clazz, methods, 1);
    if (rc != JNI_OK) { LOGE("RegisterNatives(bootstrap) 失败:%d", rc); }
    return JNI_VERSION_1_6;
}
