package com.xcj.injector

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.path
import com.xcj.injector.sign.ApkSigner
import com.xcj.injector.watermark.InjectorConstants
import com.xcj.injector.watermark.Watermark
import org.slf4j.LoggerFactory
import java.io.File

private val logger = LoggerFactory.getLogger("InjectorMain")

/**
 * 小城笺 SDK 集成辅助工具 CLI
 *
 * v2 重构:移除了 dex 字节码注入路径(红线,详见 CLAUDE.md 第 2 节)
 * 改为开发者主动集成 SDK 的辅助工具:
 *  - init:生成 gradle 依赖片段 + Application 初始化代码模板
 *  - sign:对开发者自有 APK 做签名 + 水印(可选)
 *
 * 详见 ADR 0028 (注入工具架构) / 0030 (防滥用) / 0033 (签名方案)
 */
class InjectorCommand : CliktCommand(
    name = "xcj-injector",
    help = "小城笺 SDK 集成辅助工具(生成集成代码模板 + APK 签名/水印)"
) {
    override fun run() {
        logger.info("=== 小城笺 SDK 集成辅助工具 v${InjectorConstants.VERSION} ===")
        logger.info("v2 重构:已移除 dex 注入路径,改为开发者主动集成模式")
    }
}

/**
 * init 子命令:生成 SDK 集成代码模板
 *
 * 生成:
 *  - build.gradle.kts 依赖片段(implementation("com.xcj:sdk-android:..."))
 *  - Application 初始化代码模板(XiaochengjianSDK.init(...))
 *  - AndroidManifest.xml 修改指引
 */
class InitCommand : CliktCommand(
    name = "init",
    help = "生成 SDK 集成代码模板(gradle 依赖 + Application 初始化)"
) {
    private val output by option("-o", "--output", help = "输出目录(默认 ./xcj-integration)")
        .path(canBeDir = true)
        .required()

    private val appId by option("--app-id", help = "应用 ID(在 Web 后台创建 APP 后获得)")
        .required()

    private val serverUrl by option("--server-url", help = "SaaS 服务器 URL")
        .required()

    override fun run() {
        logger.info("生成 SDK 集成模板到 $output")
        val outDir = output.toFile()
        outDir.mkdirs()

        // 1. gradle 依赖片段
        val gradleSnippet = File(outDir, "xcj-dependency.gradle.kts")
        gradleSnippet.writeText(
            """
            // === 小城笺 SDK 依赖(复制到 app/build.gradle.kts 的 dependencies 块)===
            implementation("com.xcj:sdk-android:0.2.0")

            // === SDK 需要的权限(复制到 AndroidManifest.xml)===
            // <uses-permission android:name="android.permission.INTERNET" />
            // <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
            """.trimIndent()
        )
        logger.info("已生成: ${gradleSnippet.name}")

        // 2. Application 初始化模板
        val appTemplate = File(outDir, "XcjApplication.kt")
        appTemplate.writeText(
            """
            package com.yourpackage

            import android.app.Application
            import com.xcj.sdk.XiaochengjianSDK
            import com.xcj.sdk.SdkConfig

            /**
             * Application 类:SDK 初始化入口
             *
             * 集成步骤:
             *  1. 在 AndroidManifest.xml 的 <application> 标签设置 android:name=".XcjApplication"
             *  2. 确保已在 Web 后台创建 APP,获得 appId
             *  3. 在 onCreate 中调用 XiaochengjianSDK.init(...)
             *  4. 在需要验证卡密的入口调用 XiaochengjianSDK.activate(cardKey) / validate()
             */
            class XcjApplication : Application() {
                override fun onCreate() {
                    super.onCreate()
                    val config = SdkConfig(
                        appId = "$appId",
                        serverUrl = "$serverUrl",
                        // appSecret 在 Web 后台创建 APP 时获得,建议放在 BuildConfig 或 NDK 中
                        appSecret = BuildConfig.XCJ_APP_SECRET,
                    )
                    XiaochengjianSDK.init(this, config)
                }
            }
            """.trimIndent()
        )
        logger.info("已生成: ${appTemplate.name}")

        // 3. 集成说明
        val readme = File(outDir, "README.md")
        readme.writeText(
            """
            # 小城笺 SDK 集成说明

            ## 文件清单
            - `xcj-dependency.gradle.kts` - gradle 依赖片段
            - `XcjApplication.kt` - Application 初始化模板
            - `README.md` - 本文件

            ## 集成步骤
            1. 把 `xcj-dependency.gradle.kts` 的依赖复制到 `app/build.gradle.kts`
            2. 把 `XcjApplication.kt` 复制到你的项目,改包名
            3. 在 `AndroidManifest.xml` 的 `<application>` 标签设置 `android:name=".XcjApplication"`
            4. 在 `build.gradle.kts` 的 `defaultConfig` 添加:
               ```kotlin
               buildConfigField("String", "XCJ_APP_SECRET", "\"your-app-secret\"")
               ```
            5. 编译运行 APP,SDK 会在 Application.onCreate 自动初始化
            6. 在需要验证卡密的入口调用:
               ```kotlin
               val result = XiaochengjianSDK.activate(cardKey)
               if (result.success) { /* 验证通过,放行业务 */ }
               ```

            ## SaaS 服务器
            - 当前配置的服务器:`$serverUrl`
            - 应用 ID:`$appId`

            ## 合规说明
            - SDK 只能集成到**你自有著作权**的 APP
            - 不得用于重打包他人 APK(详见 CLAUDE.md 红线)
            """.trimIndent()
        )
        logger.info("已生成: ${readme.name}")

        logger.info("=== 集成模板生成完成 ===")
        logger.info("输出目录: ${outDir.absolutePath}")
        logger.info("下一步:按 $readme 的步骤集成 SDK")
    }
}

/**
 * sign 子命令:对开发者自有 APK 做签名 + 水印
 *
 * 用途:开发者编译出自己的 APK 后,用此工具签名 + 加水印(可选)
 * 注意:此工具只签名 + 加水印,不修改 APK 内容(不注入 dex)
 */
class SignCommand : CliktCommand(
    name = "sign",
    help = "对开发者自有 APK 做签名 + 水印(不修改 APK 内容)"
) {
    private val input by option("-i", "--input", help = "输入 APK 路径(开发者自有)")
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

    private val watermarkId by option("--watermark-id", help = "水印标识(开发者 ID,可选)")
        .default("")

    private val debug by option("--debug", help = "调试模式(保留中间产物)").flag()

    override fun run() {
        logger.info("=== APK 签名 + 水印 ===")
        logger.info("输入: $input")
        logger.info("输出: $output")
        logger.info("keystore: $keystore")
        logger.info("水印 ID: ${watermarkId.ifEmpty { "(无)" }}")

        val tempDir = createTempDir(prefix = "xcj-sign-")

        try {
            require(keystore.toFile().exists()) { "keystore 文件不存在" }

            // 1. 复制 APK 到临时目录
            val workApk = tempDir.resolve("work.apk")
            input.toFile().copyTo(workApk, overwrite = true)

            // 2. 注入水印(可选)
            if (watermarkId.isNotEmpty()) {
                logger.info("[1/2] 注入水印...")
                Watermark().embed(workApk, watermarkId)
            } else {
                logger.info("[1/2] 跳过水印(未提供 --watermark-id)")
            }

            // 3. 签名(V1+V2+V3,ADR 0033)
            logger.info("[2/2] APK 签名(V1+V2+V3)...")
            ApkSigner().sign(workApk, keystore.toFile(), ksPass, ksKeyAlias, keyPass)

            // 4. 输出
            logger.info("输出 APK...")
            workApk.copyTo(output.toFile(), overwrite = true)

            logger.info("=== 签名完成 ===")
            logger.info("输出文件: $output")
            logger.info("文件大小: ${output.toFile().length() / 1024} KB")

        } catch (e: Exception) {
            logger.error("签名失败: ${e.message}", e)
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
    InjectorCommand()
        .subcommands(InitCommand(), SignCommand())
        .main(args)
}
