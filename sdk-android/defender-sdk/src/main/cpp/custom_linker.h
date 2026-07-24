/**
 * custom_linker.h - 小城笺加固 v0.2: 自实现 ELF Linker
 *
 * 完全不依赖系统 dlopen/dlsym,从内存缓冲区加载 ELF .so。
 *
 * 对抗效果:
 *  - PLT/GOT hook 全部失效(不走系统 Linker 的符号解析)
 *  - SRPatch 的 __openat hook 拦截不到(不需要 open 文件)
 *  - /proc/self/maps 中无 .so 文件名(匿名映射)
 *  - IDA 静态分析看不到加载逻辑(加密 + 自实现解析)
 *
 * 参考:
 *  - AOSP bionic/linker (linker_phdr.cpp, linker.cpp)
 *  - yuuki.cool/posts/customlinker (5 大组件架构)
 *  - 看雪 thread-269484 (基于 AOSP 的完整 demo)
 */
#ifndef CUSTOM_LINKER_H
#define CUSTOM_LINKER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============= 不透明句柄 ============= */
typedef struct cl_soinfo *cl_handle_t;

/* ============= 核心 API ============= */

/**
 * 从内存缓冲区加载 ELF .so
 *
 * @param data     ELF 数据指针(解密后的 .so 二进制)
 * @param data_len 数据长度
 * @param name     逻辑名称(用于日志和符号查找,可为 NULL)
 * @return 句柄(NULL=失败)
 */
cl_handle_t cl_dlopen_mem(const void *data, size_t data_len, const char *name);

/**
 * 在已加载的 .so 中查找导出符号
 *
 * @param handle cl_dlopen_mem 返回的句柄
 * @param symbol 符号名称
 * @return 符号地址(NULL=未找到)
 */
void *cl_dlsym(cl_handle_t handle, const char *symbol);

/**
 * 调用 .init / .init_array 构造函数
 *
 * 必须在 cl_dlopen_mem 之后、cl_dlsym 使用之前调用。
 * (dlopen_mem 内部自动完成段加载和重定位,但不调用构造函数)
 *
 * @param handle 句柄
 * @return 0=成功 / -1=失败
 */
int cl_call_constructors(cl_handle_t handle);

/**
 * 卸载(释放映射内存)
 *
 * @param handle 句柄
 */
void cl_dlclose(cl_handle_t handle);

/**
 * 获取加载基址
 */
uintptr_t cl_get_base(cl_handle_t handle);

/**
 * 获取加载大小
 */
size_t cl_get_size(cl_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* CUSTOM_LINKER_H */
