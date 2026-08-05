/**
 * x4_gc_roots.h - GC 根巡检(ADR 0098 P0-D,Virbox sub_29397C 反哺)
 *
 * 原理:
 *   Xposed/LSPosed 注入后,其框架对象(XposedBridge 类、hook 回调、模块
 *   ClassLoader 等)会驻留 JNI 全局根表。藏类名/改包名可过 FindClass 类检测,
 *   但过不了"遍历全部 GC 根"。
 *
 * 实现(v1,保守):
 *   1. 解析 libart.so 符号 JavaVMExt::VisitRoots(mangled 候选)。
 *   2. 伪造 RootVisitor(Itanium vtable 布局),sigsetjmp 全程守护。
 *   3. visitor 统计根数量,并做两条与类名无关的物理事实检测:
 *      a) 根对象地址不在任何 Java 堆/镜像映射区(dalvik-* / *.art)→ 异常根;
 *      b) JNI 全局根总数超阈值(hook 框架会注册额外全局引用)。
 *   4. 任何一步失败(符号缺失/API 不符/访问故障)→ 返回 0(跳过,不误杀)。
 *
 * 边界:
 *   - 仅 API 26-35(VisitRoots 稳定期);其余版本直接跳过。
 *   - Virbox 级的"按版本偏移表解析对象类名"属天衍增强,v1 不做。
 */
#ifndef X4_GC_ROOTS_H
#define X4_GC_ROOTS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * GC 根巡检入口
 *
 * @param java_vm JNI_OnLoad/GetJavaVM 取得的 JavaVM*(ART 中即 JavaVMExt*)
 * @return 可疑计数(0-2);0=干净或不可用(优雅降级,绝不崩溃)
 */
int x4_gc_roots_scan(void *java_vm);

/* host 单测钩子:映射区分类(纯函数,跨平台可测) */
int x4_gc_roots_range_is_heap(unsigned long start, unsigned long end, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* X4_GC_ROOTS_H */
