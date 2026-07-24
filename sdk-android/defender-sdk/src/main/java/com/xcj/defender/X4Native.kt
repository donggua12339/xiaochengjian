package com.xcj.defender

/**
 * X4 native 检测入口(ADR 0093)。
 *
 * native 方法由 defender .so 的 JNI_OnLoad 注册(x4_jni.c 的 x4_register_natives)。
 * 库经 X0 stub 加载(或 System.loadLibrary)后即注册可用。
 */
object X4Native {
    /** L1 反注入综合检测(native 侧:注入 SO + 可执行段 + ptrace)。返回可疑计数,0=干净。 */
    external fun antiInjectCheck(): Int
}
