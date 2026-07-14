package com.xcj.injector

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.path
import com.xcj.injector.dex.DexInjector
import com.xcj.injector.sign.ApkSigner
import com.xcj.injector.watermark.Watermark
import net.lingala.zip4j.ZipFile
import org.slf4j.LoggerFactory
import java.io.File

private val logger = LoggerFactory.getLogger("InjectorMain")

/**
 * 小城笺 APK 注入工具 CLI
 *
 * 详见 ADR 0011 (Smali + dex 双方案) / 0028 (注入工具架构) / 0030 (防滥用)
 *
 * 用法:
 *   java -jar xcj-injector.jar \
 *     --input app.apk \
 *     --output app-injected.apk \
 *     --keystore release.keystore \
 *     --ks-pass xxx \
 *     --ks-key-alias xcj \
 *     --key-pass xxx \
 *     --watermark-id dev123
 */
class InjectorCommand : CliktCommand(
    name = "xcj-injector",
    help = "小城笺 APK 注入工具(将 SDK 初始化代码注入到成品 APK)"
) {
    private val input by option("-i", "--input", help = "输入 APK 路径")
        .path(mustExist = true, canBeDir = false)
        .required()

    private val output by option("-o", "--output", help = "输出 APK 路径")
        .path(canBeDir = false)
        .required()

    private val keystore by option("--keystore", help = "签名 keystore 文件")
        .path(mustExist = true, canBeDir = false)
        .required()

    private val ksPass by option("--ks-pass", help = "keystore 密码").required()

    private val ksKeyAlias by option("--ks-key-alias", help = "key 别名").required()

    private val keyPass by option("--key-pass", help = "key 密码").required()

    private val watermarkId by option("--watermark-id", help = "水印标识(开发者 ID + 时间戳)")
        .required()

    private val debug by option("--debug", help = "调试模式(保留中间产物)").flag()

    override fun run() {
        logger.info("=== 小城笺 APK 注入工具 ===")
        logger.info("输入: $input")
        logger.info("输出: $output")
        logger.info("keystore: $keystore")
        logger.info("水印 ID: $watermarkId")

        val tempDir = createTempDir(prefix = "xcj-inject-")

        try {
            // 1. 强制要求 keystore(防滥用,ADR 0030)
            require(keystore.toFile().exists()) { "keystore 文件不存在" }

            // 2. 复制 APK 到临时目录
            val workApk = tempDir.resolve("work.apk")
            input.toFile().copyTo(workApk, overwrite = true)

            // 3. dex 注入(主引擎)
            logger.info("[1/4] dex 注入...")
            val dexInjector = DexInjector()
            dexInjector.inject(workApk)

            // 4. 注入水印(防滥用追溯,ADR 0030)
            logger.info("[2/4] 注入水印...")
            val watermark = Watermark()
            watermark.embed(workApk, watermarkId)

            // 5. 签名(V1+V2+V3,ADR 0033)
            logger.info("[3/4] APK 签名(V1+V2+V3)...")
            val signer = ApkSigner()
            signer.sign(workApk, keystore.toFile(), ksPass, ksKeyAlias, keyPass)

            // 6. 输出(原子操作)
            logger.info("[4/4] 输出 APK...")
            workApk.copyTo(output.toFile(), overwrite = true)

            logger.info("=== 注入完成 ===")
            logger.info("输出文件: $output")
            logger.info("文件大小: ${output.toFile().length() / 1024} KB")

        } catch (e: Exception) {
            logger.error("注入失败: ${e.message}", e)
            throw e
        } finally {
            if (!debug) {
                tempDir.deleteRecursively()
                logger.info("已清理临时目录(用 --debug 保留)")
            } else {
                logger.info("调试模式:中间产物保留在 $tempDir")
            }
        }
    }
}

fun main(args: Array<String>) {
    InjectorCommand().main(args)
}
