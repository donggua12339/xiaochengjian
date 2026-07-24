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

    /** L2 反调试综合检测(stat state + 时间差 + 断点扫描 + Frida 端口)。返回可疑计数,0=干净。 */
    external fun antiDebugCheck(): Int

    /** L3 反 dump 初始化(记录 memfd/anon:dalvik 基线 + 启动 inotify 预警线程)。须在 X0 加载后调用。 */
    external fun antiDumpInit()

    /** L3 反 dump 综合检测(rwx 段 + anon:dalvik + memfd 数量 + inotify)。返回可疑计数,0=干净。 */
    external fun antiDumpCheck(): Int

    /** L4 运行时完整性初始化(记录 libc 入口 CRC 基线等)。须在首次 check 前调用。 */
    external fun integrityInit(apkPath: String)

    /** L4 运行时完整性综合检测(libc 四入口 CRC + inline hook 指纹 + svc 签名块)。返回可疑计数,0=干净。 */
    external fun integrityCheck(apkPath: String): Int
}
