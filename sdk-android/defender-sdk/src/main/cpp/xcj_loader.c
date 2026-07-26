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
 * 密钥保护(ADR 0094):
 *   不再使用 x0_key.h 明文密钥。改为运行时从碎片重建:
 *   key[i] = X0_KEY_XOR[i] ^ X0_SALT[i](CFF 保护,IDA F5 不可读)
 *   派生函数伪装成"ABI 兼容性检查",逆向者看不到密钥用途。
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
#include "custom_linker.h"
#include "cff_params.h"   /* Hikari CFF 随机参数(ADR 0094) */
#include "x0_derive.h"    /* 密钥派生材料(ADR 0094) */
#include "x0_str_key.h"   /* 字符串解密 key 碎片(ADR 0094 防 MT 一键解密) */
#include "x0_jni_names.h" /* 随机 JNI 函数名(每构建随机) */

#define DEFENDER_TAG "XcjLoader"
#include "defender_log.h"

static JavaVM *g_vm = NULL;

/* T1 自实现 Linker 加载后的 defender 句柄(R4) */
static cl_handle_t g_defender_cl = NULL;

/* ===================================================================== */
/* Hikari CFF 保护的密钥派生链(ADR 0094 §2-3, §7)                       */
/* =====================================================================
 * IDA 视角:三个初始化函数(ABI 检查 / 日志种子 / ELF 偏移校验)
 * 实际:从碎片重建 RC4 key,CFF 状态机保护,静态分析不可读。
 *
 * 重建公式:key[i] = X0_KEY_XOR[i] ^ X0_SALT[i]
 * (X0_KEY_XOR = 原始 key ⊕ salt,构建期生成)
 */

/* "日志去重种子初始化"(实际:读 salt 并做无意义变换,增加数据流噪声) */
static uint32_t xcj_init_log_seed(void) {
    uint32_t lseed = 0;
    uint16_t state = CFF_S0;
    uint16_t sa = CFF_SA_INIT;
    int step = 0;
    uint32_t i = 0;
    while (state != CFF_EXIT) {
        switch (state) {
        case CFF_S0:
            lseed = 0x1234u;
            i = 0;
            sa = cff_next(sa, step++);  /* 辅助变量噪声 */
            state = CFF_S1;             /* 主状态直接赋值 */
            break;
        case CFF_S1:
            if (i < X0_SALT_LEN) {
                lseed ^= ((uint32_t)X0_SALT[i] << ((i & 3) * 8));
                i++;
                state = CFF_S1;
            } else {
                sa = cff_next(sa, step++);
                state = CFF_S2;
            }
            break;
        case CFF_S2:
            lseed = (lseed * 2654435761u) ^ (lseed >> 16);
            state = CFF_EXIT;
            break;
        default:
            state = CFF_EXIT;
            break;
        }
    }
    srand(lseed);
    return lseed;
}

/* "ELF 校验偏移计算"(实际:读 build_pad 做无意义变换) */
static uint32_t xcj_verify_elf_offset(void) {
    uint32_t eoff = 0;
    uint16_t sa = CFF_SA_INIT, sb = CFF_SB_INIT;
    uint16_t state = CFF_S0;
    int step = 0;
    uint32_t i = 0;
    while (state != CFF_EXIT) {
        switch (state) {
        case CFF_S0:
            eoff = 0;
            i = 0;
            sa = cff_next(sa, step++);
            state = CFF_S1;
            break;
        case CFF_S1:
            if (i < X0_BUILD_PAD_LEN) {
                eoff ^= ((uint32_t)X0_BUILD_PAD[i] << (i * 8));
                i++;
                sb = cff_next(sb, step++);
                state = CFF_S1;
            } else {
                state = CFF_S2;
            }
            break;
        case CFF_S2:
            eoff = (eoff ^ (eoff >> 11)) * 0x9E3779B9u;
            if (cff_opaque_true(sa ^ sb)) state = CFF_EXIT;
            else state = CFF_S0;  /* 僵尸:永不执行 */
            break;
        default:
            state = CFF_EXIT;
            break;
        }
    }
    return eoff;
}

/* "ABI 兼容性检查"(实际:CFF 保护的密钥重建)
 * 从 X0_KEY_XOR + X0_SALT 碎片重建 RC4 key。
 * 嵌套 CFF(技术 1)+ 多状态变量(技术 8)+ 不透明谓词(技术 6/11)
 * + 基本块切碎(技术 4)+ 僵尸代码(技术 6)。
 */
static void xcj_check_abi_compat(uint8_t *out, uint32_t len) {
    uint16_t sa = CFF_SA_INIT, sb = CFF_SB_INIT, sc = CFF_SC_INIT;
    uint16_t state = CFF_S0;
    int step = 0;
    uint32_t i = 0;

    while (state != CFF_EXIT) {
        switch (state) {
        case CFF_S0:
            i = 0;
            sa = cff_next(sa, step++);
            if (cff_opaque_true(CFF_BOGUS_X ^ sa)) {
                state = CFF_S1;
            } else {
                volatile uint32_t bogus = CFF_BOGUS_X * CFF_BOGUS_Y;
                bogus ^= CFF_BOGUS_Z;
                (void)bogus;
                state = CFF_S0;  /* 僵尸:永不执行 */
            }
            break;

        case CFF_S1:
            if (i < len) {
                /* 内层 CFF(技术 1:嵌套扁平化) */
                uint16_t inner_state = CFF_S0;
                int inner_step = 0;
                uint8_t byte_val = 0;
                while (inner_state != CFF_EXIT) {
                    switch (inner_state) {
                    case CFF_S0:
                        byte_val = X0_KEY_XOR[i];
                        sb = cff_next(sb, inner_step++);
                        inner_state = CFF_S1;
                        break;
                    case CFF_S1:
                        byte_val ^= X0_SALT[i];
                        sc = cff_next(sc, inner_step++);
                        inner_state = CFF_S2;
                        break;
                    case CFF_S2:
                        out[i] = byte_val;
                        inner_state = CFF_EXIT;
                        break;
                    default:
                        inner_state = CFF_EXIT;
                        break;
                    }
                }
                i++;
                sb = cff_next(sb, step++);
                state = CFF_S1;
            } else {
                sc = cff_next(sc, step++);
                state = CFF_S2;
            }
            break;

        case CFF_S2:
            if (cff_opaque_true(sa ^ sb ^ sc)) {
                state = CFF_EXIT;
            } else {
                state = CFF_S0;  /* 僵尸 */
            }
            break;

        default:
            state = CFF_EXIT;
            break;
        }
    }
}

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
        /* 运行时重建密钥(ADR 0094):CFF 保护,IDA 不可读 */
        uint8_t dk[X0_KEY_XOR_LEN];
        xcj_check_abi_compat(dk, X0_KEY_XOR_LEN);
        if (so_cipher_extract(frame_buf, frame_size, dk, X0_KEY_XOR_LEN,
                              plain, &plen) != 0) {
            memset(dk, 0, sizeof(dk));
            free(plain);
            continue;                                 /* 假魔数,继续扫 */
        }
        if (plen >= 4 && plain[0] == 0x7f && plain[1] == 'E' &&
            plain[2] == 'L' && plain[3] == 'F') {
            memset(dk, 0, sizeof(dk));                /* 清零派生密钥 */
            *out_len = plen;
            return plain;                             /* 命中并解密成功 */
        }
        memset(dk, 0, sizeof(dk));
        memset(plain, 0, plen);
        free(plain);                                  /* 解出非 ELF,假命中 */
    }
    return NULL;
}

static int bootstrap(const char *apk_path) {
    /* "初始化序列"(ADR 0094 §3 控制流伪装:看起来像正常初始化) */
    xcj_init_log_seed();       /* "日志种子初始化" */
    xcj_verify_elf_offset();   /* "ELF 偏移校验" */

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

    /* T1 自实现 Linker 优先(R4):匿名映射,maps 不可见,dl_iterate_phdr 枚举不到 */
    typedef jint (*jni_onload_t)(JavaVM *, void *);
    jni_onload_t on_load = NULL;

    g_defender_cl = cl_dlopen_mem(so, so_len, "libxcj_defender");
    if (g_defender_cl) {
        cl_call_constructors(g_defender_cl);

        /* 推送 cl 基址/大小给 defender 的完整性校验模块 */
        typedef void (*set_cl_info_fn)(uintptr_t, size_t);
        set_cl_info_fn si_set = (set_cl_info_fn)cl_dlsym(g_defender_cl, "self_integrity_set_cl_info");
        set_cl_info_fn sv_set = (set_cl_info_fn)cl_dlsym(g_defender_cl, "self_verify_set_cl_info");
        uintptr_t cl_base = cl_get_base(g_defender_cl);
        size_t cl_size = cl_get_size(g_defender_cl);
        if (si_set) si_set(cl_base, cl_size);
        if (sv_set) sv_set(cl_base, cl_size);

        on_load = (jni_onload_t)cl_dlsym(g_defender_cl, "JNI_OnLoad");
        if (on_load) {
            LOGI("T1 cl_dlopen_mem 成功(匿名映射)");
        } else {
            LOGE("cl_dlsym JNI_OnLoad 失败,降级 memfd");
            cl_dlclose(g_defender_cl);
            g_defender_cl = NULL;
        }
    } else {
        LOGE("cl_dlopen_mem 失败,降级 memfd+dlopen_ext");
    }

    /* 降级路径:memfd + android_dlopen_ext(原 X0 流程) */
    void *handle = NULL;
    if (!on_load) {
        handle = load_so_from_mem(so, so_len, "libxcj_payload.so");
        if (!handle) { LOGE("android_dlopen_ext 失败"); memset(so, 0, so_len); free(so); return -1; }
        on_load = (jni_onload_t)dlsym(handle, "JNI_OnLoad");
        if (!on_load) { LOGE("dlsym JNI_OnLoad 失败"); memset(so, 0, so_len); free(so); return -1; }
        LOGI("降级 memfd 加载成功");
    }

    memset(so, 0, so_len);                            /* 清理解密缓冲 */
    free(so);

    jint rc = on_load(g_vm, NULL);                    /* 手动注册载荷 native */
    LOGI("载荷 JNI_OnLoad 返回 %d", rc);

    /* ELF 头擦除(delayed erase):JNI_OnLoad 完成后,所有注册/初始化已结束。
     * 只擦 e_ident(前 16 字节),不碰后续数据(与第一个 PT_LOAD 重叠)。
     * 假 magic \x7fPRV 让扫描器命中但解析 e_type/e_machine 时全错。
     * 注意:首页可能为 r--p,需临时 mprotect RWX 再恢复。 */
    if (g_defender_cl) {
        uintptr_t base = cl_get_base(g_defender_cl);
        if (base) {
            /* 对齐到页边界 */
            uintptr_t page = base & ~0xFFFUL;
            mprotect((void *)page, 4096, PROT_READ | PROT_WRITE);
            uint8_t *hdr = (uint8_t *)base;
            hdr[0] = 0x7f; hdr[1] = 'P'; hdr[2] = 'R'; hdr[3] = 'V';
            hdr[4] = 0x00; hdr[5] = 0x00; hdr[6] = 0xFF;
            memset(hdr + 7, 0x41, 9);
            /* 恢复只读 */
            mprotect((void *)page, 4096, PROT_READ);
        }
    }

    return 0;
}

/* ===================================================================== */
/* 字符串解密 native 层(ADR 0094,防 MT 一键解密)                         */
/* =====================================================================
 * CFF 保护:从碎片重建 str_key → Base64 解码 → XOR 解密 → 返回 jstring。
 * Java 层只看到 external fun <随机名>(String): String,MT 无法跟踪。
 * 函数名每构建随机(X0_JNI_STR_DECRYPT_NAME)。
 */

/* 手写 Base64 解码表(自实现,防 libc hook) */
static int _b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int _b64_decode(const char *in, int in_len, uint8_t *out, int out_max) {
    int o = 0;
    int i = 0;
    while (i < in_len && o < out_max) {
        /* 跳过非 Base64 字符(如换行/空格) */
        int v[4] = {-1, -1, -1, -1};
        int j = 0;
        while (j < 4 && i < in_len) {
            int c = _b64_val(in[i]);
            if (c >= 0) { v[j] = c; j++; }
            i++;
        }
        if (v[0] < 0) continue;
        if (o < out_max) out[o++] = (uint8_t)((v[0] << 2) | (v[1] >= 0 ? v[1] >> 4 : 0));
        if (v[2] >= 0 && o < out_max) out[o++] = (uint8_t)(((v[1] & 0xF) << 4) | (v[2] >> 2));
        if (v[3] >= 0 && o < out_max) out[o++] = (uint8_t)(((v[2] & 0x3) << 6) | v[3]);
    }
    return o;
}

/* CFF 保护:从碎片重建 str_key(16 字节) */
static void xcj_rebuild_str_key(uint8_t *out) {
    uint16_t state = CFF_S0;
    uint16_t sa = CFF_SA_INIT;
    int step = 0;
    int frag_idx = 0;
    int byte_idx = 0;

    while (state != CFF_EXIT) {
        switch (state) {
        case CFF_S0:
            frag_idx = 0; byte_idx = 0;
            sa = cff_next(sa, step++);
            state = CFF_S1;
            break;
        case CFF_S1:
            if (frag_idx < 4) {
                /* 重建一个碎片:MASKED ⊕ PAD */
                const uint8_t *m = NULL, *p = NULL;
                switch (frag_idx) {
                case 0: m = X0_STRK_M0; p = X0_STRK_P0; break;
                case 1: m = X0_STRK_M1; p = X0_STRK_P1; break;
                case 2: m = X0_STRK_M2; p = X0_STRK_P2; break;
                case 3: m = X0_STRK_M3; p = X0_STRK_P3; break;
                }
                if (byte_idx < 4) {
                    out[frag_idx * 4 + byte_idx] = m[byte_idx] ^ p[byte_idx];
                    byte_idx++;
                    state = CFF_S1;
                } else {
                    frag_idx++;
                    byte_idx = 0;
                    sa = cff_next(sa, step++);
                    state = CFF_S1;
                }
            } else {
                state = CFF_S2;
            }
            break;
        case CFF_S2:
            if (cff_opaque_true(sa)) state = CFF_EXIT;
            else state = CFF_S0; /* 僵尸 */
            break;
        default:
            state = CFF_EXIT;
            break;
        }
    }
}

/* JNI 解密函数:CFF 保护 + 随机名 */
static jstring native_str_decrypt(JNIEnv *env, jclass clazz, jstring encoded_j) {
    (void)clazz;

    /* 运行时上下文绑定(cmdline 黑名单,边际纵深):拒绝在 jadx/apktool 等直连且 invoke
     * 本函数的进程里解密。零泄露(命中只 return 空,不输出日志)、零误杀(真 app cmdline
     * 为自身包名,不含下列特征)、开销可忽略。注:对 MT/NP 加强版无效(它们不 invoke 本
     * 函数,走 LSPlant/内置引擎),真正干死它们的是 defender_jni.c JNI_OnLoad 的 cache 路径
     * 检测;本块仅覆盖"直连逆向工具 + 走到 native 解密"这一边际路径。 */
    {
        char cmdbuf[256];
        memset(cmdbuf, 0, sizeof(cmdbuf));
        int cfd = open("/proc/self/cmdline", O_RDONLY);
        if (cfd >= 0) {
            ssize_t cn = read(cfd, cmdbuf, sizeof(cmdbuf) - 1);
            close(cfd);
            if (cn > 0) cmdbuf[cn] = 0;
        }
        static const char * const blk[] = {
            "bin.mt", "mt.plus", "jadx", "apktool", "gda", "jeb", "xposed", NULL
        };
        for (int bi = 0; blk[bi]; bi++) {
            if (strstr(cmdbuf, blk[bi])) {
                return (*env)->NewStringUTF(env, "");
            }
        }
    }

    if (!encoded_j) return NULL;
    const char *encoded = (*env)->GetStringUTFChars(env, encoded_j, NULL);
    if (!encoded) return NULL;
    int elen = (int)strlen(encoded);

    /* Base64 解码 */
    uint8_t decoded[1024];
    int dlen = _b64_decode(encoded, elen, decoded, sizeof(decoded));
    (*env)->ReleaseStringUTFChars(env, encoded_j, encoded);
    if (dlen <= 0) return (*env)->NewStringUTF(env, "");

    /* CFF 重建 str_key */
    uint8_t sk[X0_STR_KEY_LEN];
    xcj_rebuild_str_key(sk);

    /* XOR 解密 */
    uint8_t plain[1024];
    int plen = dlen < (int)sizeof(plain) - 1 ? dlen : (int)sizeof(plain) - 1;
    for (int i = 0; i < plen; i++) {
        plain[i] = decoded[i] ^ sk[i % X0_STR_KEY_LEN];
    }
    plain[plen] = '\0';  /* NewStringUTF 需要 null-terminated */
    memset(sk, 0, sizeof(sk)); /* 清零 */

    jstring result = (*env)->NewStringUTF(env, (const char *)plain);
    memset(plain, 0, (size_t)plen); /* 清零 */
    return result;
}

/* JNI:bootstrap(apkPath) -> int(0=成功)
 * 标准 JNI 命名,不需要 FindClass/RegisterNatives(避免 JNI_OnLoad ClassLoader 问题) */
JNIEXPORT jint JNICALL
Java_com_xcj_defender_DefenderX0Test_bootstrap(JNIEnv *env, jclass clazz, jstring apk_path_j) {
    (void)clazz;

    /* 注册字符串解密函数到 XcjObfStr(此时 ClassLoader 是 app 的,FindClass 可用) */
    jclass obf_clazz = (*env)->FindClass(env, "com/xcj/defender/XcjObfStr");
    if (obf_clazz) {
        JNINativeMethod obf_method = {
            X0_JNI_STR_DECRYPT_NAME,
            "(Ljava/lang/String;)Ljava/lang/String;",
            (void *)native_str_decrypt
        };
        jint orc = (*env)->RegisterNatives(env, obf_clazz, &obf_method, 1);
        if (orc != JNI_OK) { LOGE("RegisterNatives(str_decrypt) 失败"); }
        (*env)->DeleteLocalRef(env, obf_clazz);
    } else {
        LOGE("FindClass XcjObfStr 失败");
    }

    const char *apk_path = apk_path_j ? (*env)->GetStringUTFChars(env, apk_path_j, NULL) : NULL;
    if (!apk_path) return -1;
    int rc = bootstrap(apk_path);
    (*env)->ReleaseStringUTFChars(env, apk_path_j, apk_path);
    return rc;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    /* bootstrap 用标准 JNI 命名,不需要 FindClass/RegisterNatives。
     * XcjObfStr 解密函数在 bootstrap 被调用时注册(此时 ClassLoader 是 app 的)。 */
    return JNI_VERSION_1_6;
}
