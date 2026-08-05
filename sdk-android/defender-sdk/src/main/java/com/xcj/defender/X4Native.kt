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

    /** L5 SMC 自测(RC4 往返 + 执行 + 擦除 + 零 rwx 纪律)。返回 0=通过。 */
    external fun smcSelftest(): Int

    /** L5 SMC 演示敏感计算:解密加密机器码→沙箱页执行→擦除。返回 a+b。 */
    external fun smcAdd(
        a: Int,
        b: Int,
    ): Int

    /** L5 SMC 诊断:执行后沙箱页是否已擦除。1=已擦。 */
    external fun smcWiped(): Int

    /** L4 运行时完整性初始化(记录 libc 入口 CRC 基线等)。须在首次 check 前调用。 */
    external fun integrityInit(apkPath: String)

    /** L4 运行时完整性综合检测(libc 四入口 CRC + inline hook 指纹 + svc 签名块)。返回可疑计数,0=干净。 */
    external fun integrityCheck(apkPath: String): Int

    /**
     * X4 响应链初始化(ADR 0093):启动守护线程 + 三通道决策(强证据 / 有效分 / 存在感)。
     *
     * 调用后,守护线程每 3-15s 随机间隔触发一轮 check,命中强证据或有效分超阈值时
     * 按 onViolation 响应(dryRun=false 时真杀,dryRun=true 时只 log)。
     *
     * @param configPath    defender-config.json 解压后的 cache 路径;null 用默认值
     * @param selfPkg       本 APP 包名(供 exempt 检查)
     * @param apkPath       本 APK 路径(供强证据 ① 签名 hash 校验)
     * @param expectedHash  预期签名 hash(64 字符 hex;空表示不校验)
     */
    external fun x4Init(
        configPath: String?,
        selfPkg: String,
        apkPath: String,
        expectedHash: String,
    )

    /** X8 FART 脱壳扫描初始化(传入包名)。 */
    external fun antiFartInit(packageName: String)

    /** X8 FART 脱壳扫描综合检测。返回可疑计数,0=干净。 */
    external fun antiFartCheck(): Int

    /** X9 ODEX 修补检测初始化(传入 APK 路径)。 */
    external fun odexInit(apkPath: String)

    /** X9 ODEX 修补检测综合检测。返回可疑计数,0=干净。 */
    external fun odexCheck(): Int

    /**
     * GC 根巡检(ADR 0098 P0-D,Virbox sub_29397C 反哺)。
     *
     * 遍历 JNI 全局根,检出与类名无关的物理异常(堆外根 / 根数量异常),
     * 对抗藏类名/改包名的 Xposed/LSPosed 变体。
     *
     * 优雅降级:ART 符号不可得 / API 版本不符 / 访问故障 → 返回 0,绝不崩溃。
     * @return 可疑计数(0-2),0=干净或不可用
     */
    external fun gcRootScan(): Int
}
