package com.xcj.injector

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.path
import com.xcj.injector.audit.AuditAnalyzeCommand
import com.xcj.injector.audit.AuditCommand
import com.xcj.injector.audit.AuditResignCommand
import com.xcj.injector.audit.BangcleEulaCommand
import com.xcj.injector.sign.ApkSigner
import com.xcj.injector.watermark.InjectorConstants
import com.xcj.injector.watermark.Watermark
import org.slf4j.LoggerFactory
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.regex.Pattern

private val logger = LoggerFactory.getLogger("InjectorMain")

/**
 * 小城笺 SDK 集成辅助工具 CLI
 *
 * v2 重构:移除了 dex 字节码注入路径(红线,详见 CLAUDE.md 第 2 节)
 * 改为开发者主动集成 SDK 的辅助工具:
 *  - init:生成 gradle 依赖片段 + Application 初始化代码模板(可选拉取服务端公钥)
 *  - sign:对开发者自有 APK 做签名 + 水印(支持批量)
 *
 * 详见 ADR 0068 (v2 注入工具架构) / 0030 (防滥用)
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
 *  - serverPublicKey.pem(可选,--fetch-public-key 时从服务端拉取)
 */
class InitCommand : CliktCommand(
    name = "init",
    help = "生成 SDK 集成代码模板(gradle 依赖 + Application 初始化 + 可选拉取服务端公钥)"
) {
    private val output by option("-o", "--output", help = "输出目录(默认 ./xcj-integration)")
        .path(canBeDir = true)
        .required()

    private val appId by option("--app-id", help = "应用 ID(在 Web 后台创建 APP 后获得)")
        .required()

    private val serverUrl by option("--server-url", help = "SaaS 服务器 URL")
        .required()

    private val fetchPublicKey by option(
        "--fetch-public-key",
        help = "从服务端拉取 RSA 公钥(GET /v1/sdk/public-key),写入 serverPublicKey.pem"
    ).flag()

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

        // 3. 可选:从服务端拉取 RSA 公钥
        if (fetchPublicKey) {
            logger.info("[3/4] 从服务端拉取 RSA 公钥...")
            try {
                val publicKeyPem = fetchServerPublicKey(serverUrl)
                val publicKeyFile = File(outDir, "serverPublicKey.pem")
                publicKeyFile.writeText(publicKeyPem)
                logger.info("  公钥已写入: ${publicKeyFile.name}")
            } catch (e: Exception) {
                logger.error("  拉取公钥失败: ${e.message}", e)
                logger.error("  请检查 server-url 是否正确,或手动从 admin-web 下载公钥")
                throw e
            }
        } else {
            logger.info("[3/4] 跳过公钥拉取(未启用 --fetch-public-key)")
        }

        // 4. 集成说明
        val readme = File(outDir, "README.md")
        readme.writeText(
            """
            # 小城笺 SDK 集成说明

            ## 文件清单
            - `xcj-dependency.gradle.kts` - gradle 依赖片段
            - `XcjApplication.kt` - Application 初始化模板
            - `serverPublicKey.pem` - 服务端 RSA 公钥(如有 --fetch-public-key)
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

            ## RSA 公钥
            - 公钥用于 SDK handshake 时加密临时 AES 密钥(ADR 0020)
            - 公钥本就公开(开源项目),可从 `GET /v1/sdk/public-key` 拉取
            - 如未用 `--fetch-public-key` 拉取,可手动从 admin-web 下载

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

    /**
     * 从服务端拉取 RSA 公钥(PEM 格式)
     * 端点:GET /v1/sdk/public-key
     * 返回:{ "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n..." }
     */
    private fun fetchServerPublicKey(serverUrl: String): String {
        val url = serverUrl.trimEnd('/') + "/v1/sdk/public-key"
        logger.info("  GET $url")

        val client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build()
        val request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(15))
            .GET()
            .header("Accept", "application/json")
            .build()

        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != 200) {
            throw RuntimeException("HTTP ${response.statusCode()}: ${response.body().take(200)}")
        }

        // 简单 JSON 解析(避免引入 jackson 依赖)
        val body = response.body()
        val publicKeyPemPattern = Pattern.compile("\"publicKeyPem\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
        val pemMatch = publicKeyPemPattern.matcher(body)
        require(pemMatch.find()) {
            "响应中未找到 publicKeyPem 字段: ${body.take(200)}"
        }

        // 反转义 JSON 字符串
        return pemMatch.group(1)
            .replace("\\n", "\n")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    }
}

/**
 * sign 子命令:对开发者自有 APK 做签名 + 水印(支持批量)
 *
 * 用途:开发者编译出自己的 APK 后,用此工具签名 + 加水印(可选)
 * 注意:此工具只签名 + 加水印,不修改 APK 内容(不注入 dex)
 *
 * 批量模式:
 *  - 单文件:-i app.apk -o app-signed.apk
 *  - 批量(目录):-i input-dir/ -o output-dir/(签名目录下所有 .apk)
 *  - 批量(glob):用 shell 展开 .apk 通配符(如 -i "release/" 加 glob)
 */
class SignCommand : CliktCommand(
    name = "sign",
    help = "对开发者自有 APK 做签名 + 水印(支持单文件 + 批量目录)"
) {
    private val input by option("-i", "--input", help = "输入 APK 路径(单文件)或目录(批量)")
        .path(mustExist = true)
        .required()

    private val output by option("-o", "--output", help = "输出 APK 路径(单文件)或目录(批量)")
        .path(canBeDir = true)
        .required()

    private val keystore by option("--keystore", help = "签名 keystore 文件")
        .path(mustExist = true, canBeDir = false)
        .required()

    private val ksPass by option("--ks-pass", help = "keystore 密码").required()

    private val ksKeyAlias by option("--ks-key-alias", help = "key 别名").required()

    private val keyPass by option("--key-pass", help = "key 密码").required()

    private val watermarkId by option("--watermark-id", help = "水印标识(开发者 ID,可选)")
        .default("")

    private val watermarkServerUrl by option(
        "--watermark-server-url",
        help = "水印服务端 URL(SaaS 模式,如 https://xcj.winmelon.cn)。提供则用 AES-256 加密水印;不提供则走明文水印(开源模式)"
    ).default("")

    private val watermarkToken by option(
        "--watermark-token",
        help = "水印服务端 JWT(SaaS 模式,登录 admin-web 后获取)"
    ).default("")

    private val debug by option("--debug", help = "调试模式(保留中间产物)").flag()

    override fun run() {
        val inputFile = input.toFile()
        val outputFile = output.toFile()

        if (inputFile.isDirectory) {
            // 批量模式:输入是目录,输出必须是目录
            require(outputFile.isDirectory || !outputFile.exists()) {
                "批量模式:--output 必须是目录(当前是文件: $outputFile)"
            }
            outputFile.mkdirs()
            signBatch(inputFile, outputFile)
        } else {
            // 单文件模式
            require(!outputFile.isDirectory) {
                "单文件模式:--output 必须是文件路径(当前是目录: $outputFile)"
            }
            outputFile.parentFile?.mkdirs()
            signSingle(inputFile, outputFile)
        }
    }

    /**
     * 单文件签名
     */
    private fun signSingle(inputApk: File, outputApk: File) {
        logger.info("=== APK 签名 + 水印(单文件)===")
        logger.info("输入: ${inputApk.absolutePath}")
        logger.info("输出: ${outputApk.absolutePath}")
        logger.info("keystore: $keystore")
        logger.info("水印 ID: ${watermarkId.ifEmpty { "(无)" }}")
        if (watermarkServerUrl.isNotEmpty()) {
            logger.info("水印模式: SaaS(AES-256-GCM 加密,密钥服务端持有)")
        } else if (watermarkId.isNotEmpty()) {
            logger.info("水印模式: 开源(明文,deprecated)")
        }

        val tempDir = createTempDir(prefix = "xcj-sign-")
        try {
            val workApk = tempDir.resolve("work.apk")
            inputApk.copyTo(workApk, overwrite = true)

            if (watermarkServerUrl.isNotEmpty()) {
                // SaaS 模式:调后端拿加密水印
                require(watermarkToken.isNotEmpty()) { "SaaS 模式需提供 --watermark-token" }
                require(watermarkId.isNotEmpty()) { "SaaS 模式需提供 --watermark-id" }
                logger.info("[1/2] 从服务端拉取加密水印...")
                val watermarkBase64 = fetchEncryptedWatermark(watermarkServerUrl, watermarkToken, watermarkId)
                Watermark().embedEncrypted(workApk, watermarkBase64)
            } else if (watermarkId.isNotEmpty()) {
                // 开源模式:明文水印(deprecated)
                logger.info("[1/2] 注入明文水印(开源模式,推荐改用 --watermark-server-url)...")
                Watermark().embed(workApk, watermarkId)
            } else {
                logger.info("[1/2] 跳过水印(未提供 --watermark-id)")
            }

            logger.info("[2/2] APK 签名(V1+V2+V3)...")
            ApkSigner().sign(workApk, keystore.toFile(), ksPass, ksKeyAlias, keyPass)

            workApk.copyTo(outputApk, overwrite = true)
            logger.info("=== 签名完成 ===")
            logger.info("输出文件: ${outputApk.absolutePath}")
            logger.info("文件大小: ${outputApk.length() / 1024} KB")
        } catch (e: Exception) {
            logger.error("签名失败: ${e.message}", e)
            throw e
        } finally {
            if (!debug) {
                tempDir.deleteRecursively()
            } else {
                logger.info("调试模式:中间产物保留在 $tempDir")
            }
        }
    }

    /**
     * 批量签名(目录下所有 .apk)
     */
    private fun signBatch(inputDir: File, outputDir: File) {
        val apks: Array<File> = inputDir.listFiles { f -> f.extension.equals("apk", ignoreCase = true) }
            ?: emptyArray()

        if (apks.isEmpty()) {
            logger.warn("输入目录无 .apk 文件: ${inputDir.absolutePath}")
            return
        }

        logger.info("=== APK 批量签名 + 水印 ===")
        logger.info("输入目录: ${inputDir.absolutePath}")
        logger.info("输出目录: ${outputDir.absolutePath}")
        logger.info("待签名 APK 数: ${apks.size}")
        logger.info("keystore: $keystore")
        logger.info("水印 ID: ${watermarkId.ifEmpty { "(无)" }}")

        var success = 0
        var failed = 0
        val failures = mutableListOf<Pair<File, Exception>>()

        apks.sortedBy { it.name }.forEachIndexed { idx, apk ->
            val outputApk = outputDir.resolve(apk.nameWithoutExtension + "-signed.apk")
            logger.info("[${idx + 1}/${apks.size}] 签名: ${apk.name}")
            try {
                signSingleQuiet(apk, outputApk)
                success++
            } catch (e: Exception) {
                failed++
                failures.add(apk to e)
                logger.error("  失败: ${e.message}")
            }
        }

        logger.info("=== 批量签名完成 ===")
        logger.info("成功: $success / ${apks.size}")
        if (failed > 0) {
            logger.warn("失败: $failed")
            failures.forEach { (apk, e) ->
                logger.warn("  - ${apk.name}: ${e.message}")
            }
            throw RuntimeException("批量签名有 $failed 个失败")
        }
    }

    /**
     * 静默签名(批量时用,不重复打印 header)
     */
    private fun signSingleQuiet(inputApk: File, outputApk: File) {
        val tempDir = createTempDir(prefix = "xcj-sign-${inputApk.nameWithoutExtension}-")
        try {
            val workApk = tempDir.resolve("work.apk")
            inputApk.copyTo(workApk, overwrite = true)

            if (watermarkServerUrl.isNotEmpty()) {
                val watermarkBase64 = fetchEncryptedWatermark(watermarkServerUrl, watermarkToken, watermarkId)
                Watermark().embedEncrypted(workApk, watermarkBase64)
            } else if (watermarkId.isNotEmpty()) {
                Watermark().embed(workApk, watermarkId)
            }

            ApkSigner().sign(workApk, keystore.toFile(), ksPass, ksKeyAlias, keyPass)
            workApk.copyTo(outputApk, overwrite = true)
            logger.info("  输出: ${outputApk.name} (${outputApk.length() / 1024} KB)")
        } finally {
            if (!debug) {
                tempDir.deleteRecursively()
            }
        }
    }

    /**
     * 从服务端拉取 AES-256-GCM 加密水印(ADR 0030 §c SaaS 模式)
     *
     * 端点:POST /v1/watermark/generate
     * 请求体:{ watermarkId, version? }
     * 响应:{ watermarkBase64, version, algorithm }
     */
    private fun fetchEncryptedWatermark(
        serverUrl: String,
        token: String,
        watermarkId: String,
    ): String {
        val url = serverUrl.trimEnd('/') + "/v1/watermark/generate"
        logger.info("  POST $url")

        val requestBody = """{"watermarkId":"${watermarkId.replace("\"", "\\\"")}","version":"${InjectorConstants.VERSION}"}"""
        val client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build()
        val request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(15))
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer $token")
            .build()

        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != 200 && response.statusCode() != 201) {
            throw RuntimeException("水印生成失败: HTTP ${response.statusCode()}: ${response.body().take(200)}")
        }

        val body = response.body()
        val watermarkRegex = Pattern.compile("\"watermarkBase64\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
        val match = watermarkRegex.matcher(body)
        require(match.find()) {
            "响应中未找到 watermarkBase64 字段: ${body.take(200)}"
        }
        return match.group(1).replace("\\\"", "\"").replace("\\\\", "\\")
    }
}

fun main(args: Array<String>) {
    InjectorCommand()
        .subcommands(
            InitCommand(),
            SignCommand(),
            AuditCommand().subcommands(
                AuditAnalyzeCommand(),
                AuditResignCommand(),
                BangcleEulaCommand(),
            ),
        )
        .main(args)
}
