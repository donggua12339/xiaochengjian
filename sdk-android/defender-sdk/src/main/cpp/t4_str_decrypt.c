/**
 * t4_str_decrypt.c - T4 DEX 字符串解密 native 实现(ADR 0090)
 *
 * 运行时被 DexStringDecryptor.get(index) 调用:
 *   1. 从 Java 层 XcjEncStringTable.DATA[index] 取加密 byte[]
 *   2. XOR 解密(key 在 t4_str_key.h,受 X0 SO 加密保护)
 *   3. 返回 UTF-8 jstring
 *
 * 安全:密钥不以明文出现在 DEX/Java 层;静态分析 DEX 只能看到密文 byte[]。
 */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

/* 构建期生成的密钥头文件(由 injector encrypt-strings --key-header 产出) */
#ifdef T4_ENABLED
#include "t4_str_key.h"
#include "vm_engine.h"
#include "vm_bytecode.h"
/* 白盒 S-box(可选,由 build_whitebox_key.py 生成;存在时替代 VMP XOR) */
#if __has_include("wb_sbox.h")
#include "wb_sbox.h"
#define T4_USE_WHITEBOX 1
#endif
#endif

#define DEFENDER_TAG "T4StrDecrypt"
#include "defender_log.h"

#ifdef T4_ENABLED

/**
 * JNI: com.xcj.defender.DexStringDecryptor.get(I)Ljava/lang/String;
 */
static jstring t4_get(JNIEnv *env, jclass clazz, jint index) {
    (void)clazz;

    /* 1. 获取 XcjEncStringTable.DATA 数组 */
    jclass tableClass = (*env)->FindClass(env, "com/xcj/defender/XcjEncStringTable");
    if (!tableClass) {
        LOGE("T4: FindClass XcjEncStringTable 失败");
        return (*env)->NewStringUTF(env, "");
    }

    jfieldID dataField = (*env)->GetStaticFieldID(env, tableClass, "DATA", "[[B");
    if (!dataField) {
        LOGE("T4: GetStaticFieldID DATA 失败");
        (*env)->DeleteLocalRef(env, tableClass);
        return (*env)->NewStringUTF(env, "");
    }

    jobjectArray dataArray = (jobjectArray)(*env)->GetStaticObjectField(env, tableClass, dataField);
    (*env)->DeleteLocalRef(env, tableClass);
    if (!dataArray) {
        LOGE("T4: DATA 为 null");
        return (*env)->NewStringUTF(env, "");
    }

    /* 2. 边界检查 */
    jsize len = (*env)->GetArrayLength(env, dataArray);
    if (index < 0 || index >= len) {
        LOGE("T4: index 越界");
        (*env)->DeleteLocalRef(env, dataArray);
        return (*env)->NewStringUTF(env, "");
    }

    /* 3. 取加密 byte[] */
    jbyteArray encBytes = (jbyteArray)(*env)->GetObjectArrayElement(env, dataArray, index);
    (*env)->DeleteLocalRef(env, dataArray);
    if (!encBytes) {
        return (*env)->NewStringUTF(env, "");
    }

    jsize byteLen = (*env)->GetArrayLength(env, encBytes);
    if (byteLen <= 0) {
        (*env)->DeleteLocalRef(env, encBytes);
        return (*env)->NewStringUTF(env, "");
    }

    /* 4. 解密:白盒 S-box 优先 → VMP XOR 回退 */
    jbyte *encData = (*env)->GetByteArrayElements(env, encBytes, NULL);
    char *plain = (char *)malloc((size_t)byteLen + 1);
    if (!plain) {
        (*env)->ReleaseByteArrayElements(env, encBytes, encData, JNI_ABORT);
        (*env)->DeleteLocalRef(env, encBytes);
        return (*env)->NewStringUTF(env, "");
    }

#ifdef T4_USE_WHITEBOX
    /* 白盒解密: plain[i] = WB_SBOX[i % WB_KEY_LEN][enc[i]] */
    for (jsize i = 0; i < byteLen; i++) {
        plain[i] = (char)WB_SBOX[i % WB_KEY_LEN][(uint8_t)encData[i]];
    }
#else
    /* VMP 解密(T2:通过 VM 引擎执行 XOR,IDA 只看到 dispatch loop) */
    memcpy(plain, encData, (size_t)byteLen);
    vm_context_t vm;
    vm_init(&vm, VM_BC_xor_decrypt, VM_BC_xor_decrypt_size);
    vm_set_arg(&vm, 0, (uint64_t)(uintptr_t)plain);
    vm_set_arg(&vm, 1, (uint64_t)(uintptr_t)T4_XOR_KEY);
    vm_set_arg(&vm, 2, (uint64_t)(uint32_t)byteLen);
    vm_set_arg(&vm, 3, (uint64_t)T4_XOR_KEY_LEN);
    vm_execute(&vm);
#endif

    plain[byteLen] = '\0';

    /* 5. 清理加密数据引用 */
    (*env)->ReleaseByteArrayElements(env, encBytes, encData, JNI_ABORT);
    (*env)->DeleteLocalRef(env, encBytes);

    /* 6. 返回 jstring */
    jstring result = (*env)->NewStringUTF(env, plain);

    /* 7. 清零明文(用后擦除) */
    memset(plain, 0, (size_t)byteLen);
    free(plain);

    return result;
}

/**
 * 注册 T4 native 方法(由 defender JNI_OnLoad 调用)。
 */
int t4_register_natives(JNIEnv *env) {
    jclass clazz = (*env)->FindClass(env, "com/xcj/defender/DexStringDecryptor");
    if (!clazz) return -1;

    JNINativeMethod methods[] = {
        {"get", "(I)Ljava/lang/String;", (void *)t4_get},
    };

    jint rc = (*env)->RegisterNatives(env, clazz, methods, 1);
    (*env)->DeleteLocalRef(env, clazz);
    return (rc == JNI_OK) ? 0 : -1;
}

#else /* T4_ENABLED not defined */

int t4_register_natives(JNIEnv *env) {
    (void)env;
    return 0;  /* T4 未启用,静默跳过 */
}

#endif /* T4_ENABLED */
