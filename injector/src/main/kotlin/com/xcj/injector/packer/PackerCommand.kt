package com.xcj.injector.packer

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.path
import org.slf4j.LoggerFactory
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.time.Duration
import java.util.Base64

private val logger = LoggerFactory.getLogger("PackerCommand")

/**
 * packer 子命令:自有 APK SDK 封装(ADR 0081)
 *
 * 子命令:
 *  - pack: 上传 APK + Keystore + classes-xcj.dex,执行封装(七锁校验)
 *  - logs: 查询封装历史
 *
 * 七锁架构(律师预审 2026-07-21 通过):
 *  锁 1 对象锁定(三重校验,后端强制)
 *  锁 2 内容锁定(固定 classes-xcj.dex 白名单,后端校验)
 *  锁 3 入口锁定(Manifest 修改范围,后端校验)
 *  锁 4 签名锁定(自备 Keystore,本 CLI 上传)
 *  锁 5 权限锁定(JWT 开发者自身,后端校验)
 *  锁 6 数据锁定(SDK 配置仅 OAID + 包信息)
 *  锁 7 客户端签名自检(后端配置预期 hash,SDK 运行时校验)
 *
 * 详见 ADR 0081(自有 APK 的 xcj-auth-sdk 封装器)
 */
class PackerCommand : CliktCommand(
    name = "packer",
    help = "自有 APK SDK 封装(七锁校验,ADR 0081)"
) {
    override fun run() {
        logger.info("=== 小城笺自有 APK SDK 封装(ADR 0081)===")
    }
}

/**
 * packer pack 子命令:执行 SDK 封装
 */
class PackerPackCommand : CliktCommand(
    name = "pack",
    help = "上传 APK + Keystore + classes-xcj.dex,执行封装(七锁校验)"
) {
    private val apk by option("--apk", help = "自有 APK 文件")
        .path(mustExist = true, canBeDir = false)
        .required()

    private val keystore by option("--keystore", help = "自备 Keystore(.jks/.keystore)")
        .path(mustExist = true, canBeDir = false)
        .required()

    private val xcjAuthSdkDex by option("--xcj-auth-sdk-dex", help = "xcj-auth-sdk 编译产物(classes-xcj.dex)")
        .path(mustExist = true, canBeDir = false)
        .required()

    private val ksPass by option("--ks-pass", help = "Keystore 密码").required()
    private val keyAlias by option("--ks-key-alias", help = "key 别名").required()
    private val keyPass by option("--key-pass", help = "key 密码").required()

    private val appId by option("--app-id", help = "应用 ID(可选,SDK 配置)")
        .default("")

    private val serverUrl by option("--server-url", help = "SaaS 服务器 URL(默认 https://xcj.winmelon.cn)")
        .default("https://xcj.winmelon.cn")

    private val token by option("--token", help = "管理员 JWT").required()

    private val output by option("-o", "--output", help = "封装后 APK 输出路径(默认 <apk-name>-packed.apk)")
        .path(canBeDir = false)

    override fun run() {
        logger.info("=== 自有 APK SDK 封装(七锁校验,ADR 0081)===")
        logger.info("APK: ${apk.toAbsolutePath()}")
        logger.info("Keystore: ${keystore.toAbsolutePath()}")
        logger.info("classes-xcj.dex: ${xcjAuthSdkDex.toAbsolutePath()}")
        logger.info("服务器: $serverUrl")

        val apkFile = apk.toFile()
        val keystoreFile = keystore.toFile()
        val xcjAuthSdkDexFile = xcjAuthSdkDex.toFile()

        if (!apkFile.exists()) throw RuntimeException("APK 文件不存在")
        if (!keystoreFile.exists()) throw RuntimeException("Keystore 文件不存在")
        if (!xcjAuthSdkDexFile.exists()) throw RuntimeException("classes-xcj.dex 文件不存在")

        val outPath = output?.toFile()
            ?: File(apkFile.parentFile, apkFile.nameWithoutExtension + "-packed.apk")

        // 构建 multipart/form-data 请求
        val boundary = "xcj-packer-boundary-${System.currentTimeMillis()}"
        val multipartBody = buildMultipartBody(
            boundary,
            apkFile,
            keystoreFile,
            xcjAuthSdkDexFile,
            ksPass,
            keyAlias,
            keyPass,
            appId,
            serverUrl,
        )

        val url = "$serverUrl/v1/packer/pack"
        val client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build()
        val request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofMinutes(5))
            .POST(HttpRequest.BodyPublishers.ofByteArray(multipartBody))
            .header("Content-Type", "multipart/form-data; boundary=$boundary")
            .header("Authorization", "Bearer $token")
            .build()

        logger.info("上传 APK + Keystore + classes-xcj.dex,后端七锁校验 + 封装中...")
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != 200 && response.statusCode() != 201) {
            logger.error("封装失败: HTTP ${response.statusCode()}")
            logger.error("响应: ${response.body().take(500)}")
            throw RuntimeException("PACK_FAILED: HTTP ${response.statusCode()}")
        }

        val body = response.body()

        // 提取 packedApkBase64
        val base64Regex = Regex("\"packedApkBase64\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
        val base64Match = base64Regex.find(body)
            ?: throw RuntimeException("响应未含 packedApkBase64 字段")
        val base64Data = base64Match.groupValues[1]
            .replace("\\n", "")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")

        val packedApk = Base64.getDecoder().decode(base64Data)
        Files.write(outPath.toPath(), packedApk)

        // 提取其他字段
        val taskIdRegex = Regex("\"taskId\"\\s*:\\s*\"([^\"]+)\"")
        val packedApkHashRegex = Regex("\"packedApkHash\"\\s*:\\s*\"([^\"]+)\"")
        val injectedDexHashRegex = Regex("\"injectedDexHash\"\\s*:\\s*\"([^\"]+)\"")

        val taskId = taskIdRegex.find(body)?.groupValues?.get(1) ?: "(unknown)"
        val packedApkHash = packedApkHashRegex.find(body)?.groupValues?.get(1) ?: "(unknown)"
        val injectedDexHash = injectedDexHashRegex.find(body)?.groupValues?.get(1) ?: "(unknown)"

        logger.info("=== 封装完成(七锁校验通过)===")
        logger.info("输出: ${outPath.absolutePath}")
        logger.info("大小: ${packedApk.size / 1024} KB")
        logger.info("taskId: $taskId")
        logger.info("封装后 APK hash: $packedApkHash")
        logger.info("注入 dex hash: $injectedDexHash")
    }

    private fun buildMultipartBody(
        boundary: String,
        apkFile: File,
        keystoreFile: File,
        xcjAuthSdkDexFile: File,
        ksPass: String,
        keyAlias: String,
        keyPass: String,
        appId: String,
        serverUrl: String,
    ): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(baos)

        fun writeFileField(name: String, file: File, contentType: String) {
            dos.writeBytes("--$boundary\r\n")
            dos.writeBytes("Content-Disposition: form-data; name=\"$name\"; filename=\"${file.name}\"\r\n")
            dos.writeBytes("Content-Type: $contentType\r\n")
            dos.writeBytes("\r\n")
            dos.write(file.readBytes())
            dos.writeBytes("\r\n")
        }

        fun writeField(name: String, value: String) {
            dos.writeBytes("--$boundary\r\n")
            dos.writeBytes("Content-Disposition: form-data; name=\"$name\"\r\n")
            dos.writeBytes("\r\n")
            dos.writeBytes(value)
            dos.writeBytes("\r\n")
        }

        // APK
        writeFileField("apk", apkFile, "application/vnd.android.package-archive")

        // Keystore
        writeFileField("keystore", keystoreFile, "application/octet-stream")

        // classes-xcj.dex
        writeFileField("xcjAuthSdkDex", xcjAuthSdkDexFile, "application/octet-stream")

        // Keystore 凭证
        writeField("keystorePassword", ksPass)
        writeField("keyAlias", keyAlias)
        writeField("keyPassword", keyPass)

        // SDK 配置
        val sdkConfig = buildString {
            append("{")
            append("\"appId\":\"$appId\",")
            append("\"serverUrl\":\"$serverUrl\",")
            append("\"offlineCacheDays\":7,")
            append("\"oaidEnabled\":true")
            append("}")
        }
        writeField("sdkConfig", sdkConfig)
        writeField("originalName", apkFile.name)

        dos.writeBytes("--$boundary--\r\n")
        dos.flush()
        return baos.toByteArray()
    }
}

/**
 * packer logs 子命令:查询封装历史
 */
class PackerLogsCommand : CliktCommand(
    name = "logs",
    help = "查询封装历史"
) {
    private val serverUrl by option("--server-url", help = "SaaS 服务器 URL")
        .default("https://xcj.winmelon.cn")

    private val token by option("--token", help = "管理员 JWT").required()

    private val limit by option("--limit", help = "返回条数(默认 50)")
        .default("50")

    override fun run() {
        logger.info("=== 封装历史 ===")

        val url = "$serverUrl/v1/packer/logs?limit=$limit"
        val client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build()
        val request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(15))
            .GET()
            .header("Authorization", "Bearer $token")
            .build()

        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() != 200) {
            throw RuntimeException("查询失败: HTTP ${response.statusCode()}: ${response.body().take(300)}")
        }

        println(response.body())
    }
}
