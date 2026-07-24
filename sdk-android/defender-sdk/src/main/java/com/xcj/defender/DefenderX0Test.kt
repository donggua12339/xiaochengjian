package com.xcj.defender

/**
 * X0-3 原型测试入口。
 *
 * 加载 stub libxcj_loader.so,其 JNI_OnLoad 会自举:RC4 解密嵌入载荷 → memfd →
 * android_dlopen_ext → 手动调载荷的 JNI_OnLoad,把本类的 native [ping] 注册上。
 * [ping] 返回 "pong-from-memfd-x0" 即证明"加密 .so → memfd → 手动 JNI_OnLoad"核心链路通。
 *
 * 原型跑通后,此类与 x0test 载荷会替换为真外壳 libxcj_defender.so(见 ADR 0092)。
 */
class DefenderX0Test {
    companion object {
        init {
            System.loadLibrary("xcj_loader")
        }

        @JvmStatic
        external fun ping(): String
    }
}
