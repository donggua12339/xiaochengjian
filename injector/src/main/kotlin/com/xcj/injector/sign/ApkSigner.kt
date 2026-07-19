package com.xcj.injector.sign

import org.slf4j.LoggerFactory
import java.io.File

/**
 * APK 签名器(V1 + V2 + V3)
 *
 * 详见 ADR 0030 (防滥用机制,签名方案部分)
 *
 * 实现:调用 Android SDK 的 apksigner 工具
 * 路径:$ANDROID_HOME/build-tools/<version>/apksigner.bat
 */
class ApkSigner {
    private val logger = LoggerFactory.getLogger(ApkSigner::class.java)

    /**
     * 签名 APK
     *
     * @param apkFile 待签名的 APK
     * @param keystore keystore 文件
     * @param ksPass keystore 密码
     * @param ksKeyAlias key 别名
     * @param keyPass key 密码
     */
    fun sign(
        apkFile: File,
        keystore: File,
        ksPass: String,
        ksKeyAlias: String,
        keyPass: String,
    ) {
        val apksigner = findApksigner()
        require(apksigner != null) {
            "apksigner 未找到,请安装 Android SDK Build-Tools"
        }

        val cmd = listOf(
            apksigner.absolutePath,
            "sign",
            "--ks", keystore.absolutePath,
            "--ks-pass", "pass:$ksPass",
            "--ks-key-alias", ksKeyAlias,
            "--key-pass", "pass:$keyPass",
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true",
            apkFile.absolutePath,
        )

        logger.info("执行签名: ${apksigner.name}")
        val process = ProcessBuilder(cmd)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        if (exitCode != 0) {
            logger.error("签名失败: $output")
            throw RuntimeException("APK_SIGN_FAILED: $output")
        }
        logger.info("签名完成(V1+V2+V3)")
    }

    /**
     * 查找 apksigner
     * 路径:$ANDROID_HOME/build-tools/<version>/apksigner(.bat)
     */
    private fun findApksigner(): File? {
        val androidHome = System.getenv("ANDROID_HOME")
            ?: System.getenv("ANDROID_SDK_ROOT")
            ?: return null
        val buildToolsDir = File(androidHome, "build-tools")
        if (!buildToolsDir.exists()) return null
        // 取最新版本
        val versionDir = buildToolsDir.listFiles()?.maxByOrNull { it.name }
            ?: return null
        val apksigner = File(versionDir, if (System.getProperty("os.name").lowercase().contains("win")) "apksigner.bat" else "apksigner")
        return if (apksigner.exists()) apksigner else null
    }
}
