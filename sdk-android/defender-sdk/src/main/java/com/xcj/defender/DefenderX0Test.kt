package com.xcj.defender

/**
 * X0-3 原型测试入口。
 *
 * 加载 stub libxcj_loader.so(其 JNI_OnLoad 注册 [bootstrap]);调 [bootstrap] 触发
 * stub 自举:mmap APK → 扫 XCJSO1 魔数 → RC4 解密 → memfd → android_dlopen_ext →
 * 手动调载荷 JNI_OnLoad(注册 [ping])。[ping] 返回 pong-from-memfd-x0 即核心链路通。
 *
 * 原型载荷 = x0test;跑通后换真外壳 libxcj_defender.so(见 ADR 0092)。
 */
class DefenderX0Test {
    companion object {
        init {
            System.loadLibrary("xcj_loader")
        }

        /** stub 注册:定位并加载 APK 中的加密载荷。返回 0=成功。 */
        @JvmStatic
        external fun bootstrap(apkPath: String): Int

        /** 载荷(x0test)注册:验证用。 */
        @JvmStatic
        external fun ping(): String
    }
}
