package com.xcj.injector.audit

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.path
import org.slf4j.LoggerFactory
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.Base64

private val logger = LoggerFactory.getLogger("AuditCommand")

/**
 * audit 子命令:自有 APK 诊断 + 签名回填(ADR 0077)
 *
 * 子命令:
 *  - analyze: 上传 APK 到后端做只读诊断(JADX 反编译查看 + 签名信息 + SDK 后门扫描)
 *  - resign:  上传 APK + keystore,后端做签名回填(META-INF only,V1+V2+V3,hash 自动入白名单)
 *
 * 三重校验在后端执行(包名白名单 + 签名 hash 比对 + 目录隔离),CLI 不绕过。
 *
 * 详见 ADR 0077(自有 APK 诊断功能,含技术兜底)
 */
class AuditCommand : CliktCommand(
    name = "audit",
    help = "自有 APK 诊断 + 签名回填 + 梆梆加固自检(ADR 0077/0078,需先在 admin-web 注册包名 + 配置签名 hash)"
) {
    override fun run() {
        logger.info("=== 小城笺自有 APK 诊断工具(ADR 0077/0078)===")
        logger.info("子命令:analyze(只读诊断)/ resign(签名回填)/ bangcle-eula(梆梆 EULA)/ bangcle(梆梆自检)")
        logger.info("三重校验在后端执行,CLI 不绕过")
    }
}

/**
 * audit analyze 子命令:上传 APK 做只读诊断
 *
 * 流程:
 *  1. 读取本地 APK
 *  2. POST /v1/audit/analyze(multipart/form-data,带 JWT)
 *  3. 接收诊断报告 JSON
 *  4. 可选写入本地文件(--output)
 */
class AuditAnalyzeCommand : CliktCommand(
    name = "analyze",
    help = "上传自有 APK 到后端做只读诊断(JADX/签名/SDK 后门扫描)"
) {
    private val apk by option("--apk", help = "自有 APK 文件路径")
        .path(mustExist = true, canBeDir = false)
        .required()

    private val appId by option("--app-id", help = "应用 ID(在 admin-web 创建 APP 后获得)")
        .required()

    private val serverUrl by option("--server-url", help = "SaaS 服务器 URL(如 https://xcj.winmelon.cn)")
        .required()

    private val token by option("--token", help = "管理员 JWT(登录 admin-web 后获取)")
        .required()

    private val output by option("-o", "--output", help = "报告输出路径(默认输出到 stdout)")
        .path(canBeDir = false)

    private val hardener by option(
        "--hardener",
        help = "加固厂商(可选:bangcle。未指定则普通诊断;指定 bangcle 触发梆梆自检,ADR 0078)"
    ).default("")

    override fun run() {
        logger.info("=== 自有 APK 诊断(只读)===")
        logger.info("APK: ${apk.toAbsolutePath()}")
        logger.info("appId: $appId")
        logger.info("服务器: $serverUrl")
        if (hardener == "bangcle") {
            logger.info("加固厂商: 梆梆(ADR 0078,需先接受 EULA)")
        }

        val apkFile = apk.toFile()
        if (!apkFile.exists()) {
            throw RuntimeException("APK 文件不存在: ${apk.toAbsolutePath()}")
        }
        val apkSize = apkFile.length()
        logger.info("APK 大小: ${apkSize / 1024} KB")

        // 构建 multipart/form-data 请求
        val boundary = "xcj-audit-boundary-${System.currentTimeMillis()}"
        val multipartBody = buildMultipartBody(boundary, apkFile)

        // 梆梆自检走 ?hardener=bangcle,普通诊断走默认端点
        val url = if (hardener == "bangcle") {
            "$serverUrl/v1/audit/analyze?hardener=bangcle"
        } else {
            "$serverUrl/v1/audit/analyze"
        }
        val client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build()
        val request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofMinutes(35)) // 诊断超时 30 分钟 + 余量
            .POST(HttpRequest.BodyPublishers.ofByteArray(multipartBody))
            .header("Content-Type", "multipart/form-data; boundary=$boundary")
            .header("Authorization", "Bearer $token")
            .build()

        logger.info("上传 APK + 诊断中(可能需要数分钟)...")
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != 200 && response.statusCode() != 201) {
            logger.error("诊断失败: HTTP ${response.statusCode()}")
            logger.error("响应: ${response.body().take(500)}")
            throw RuntimeException("AUDIT_ANALYZE_FAILED: HTTP ${response.statusCode()}")
        }

        val report = response.body()
        logger.info("=== 诊断完成 ===")

        if (output != null) {
            output!!.toFile().writeText(report)
            logger.info("报告已写入: ${output!!.toAbsolutePath()}")
        } else {
            println(report)
        }
    }

    /**
     * 构建 multipart/form-data 请求体
     */
    private fun buildMultipartBody(boundary: String, apkFile: File): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(baos)

        // apk 字段
        dos.writeBytes("--$boundary\r\n")
        dos.writeBytes("Content-Disposition: form-data; name=\"apk\"; filename=\"${apkFile.name}\"\r\n")
        dos.writeBytes("Content-Type: application/vnd.android.package-archive\r\n")
        dos.writeBytes("\r\n")
        dos.write(apkFile.readBytes())
        dos.writeBytes("\r\n")

        // originalName 字段
        dos.writeBytes("--$boundary\r\n")
        dos.writeBytes("Content-Disposition: form-data; name=\"originalName\"\r\n")
        dos.writeBytes("\r\n")
        dos.writeBytes(apkFile.name)
        dos.writeBytes("\r\n")

        dos.writeBytes("--$boundary--\r\n")
        dos.flush()
        return baos.toByteArray()
    }
}

/**
 * audit resign 子命令:签名回填(例外 A,ADR 0077 §2.1)
 *
 * 流程:
 *  1. 读取本地 APK + keystore
 *  2. POST /v1/audit/resign(multipart/form-data,带 JWT + keystore + 凭证)
 *  3. 接收重签后的 APK(base64 编码)
 *  4. 写入本地文件
 *
 * 约束(后端强制,CLI 不绕过):
 *  - 仅修改 META-INF/(apksigner 只生成签名块)
 *  - 必须使用自有 keystore
 *  - V1+V2+V3 签名
 *  - 回填后 hash 自动入白名单
 *  - 三重校验前置(包名白名单 + 签名 hash 比对 + 目录隔离)
 */
class AuditResignCommand : CliktCommand(
    name = "resign",
    help = "签名回填(META-INF only + 自有 keystore + V1+V2+V3 + hash 入白名单)"
) {
    private val apk by option("--apk", help = "自有 APK 文件路径")
        .path(mustExist = true, canBeDir = false)
        .required()

    private val keystore by option("--keystore", help = "开发者自有 keystore 文件(.jks/.keystore)")
        .path(mustExist = true, canBeDir = false)
        .required()

    private val ksPass by option("--ks-pass", help = "keystore 密码").required()

    private val keyAlias by option("--ks-key-alias", help = "key 别名").required()

    private val keyPass by option("--key-pass", help = "key 密码").required()

    private val serverUrl by option("--server-url", help = "SaaS 服务器 URL")
        .required()

    private val token by option("--token", help = "管理员 JWT").required()

    private val output by option("-o", "--output", help = "重签 APK 输出路径(默认 <apk-name>-resigned.apk)")
        .path(canBeDir = false)

    override fun run() {
        logger.info("=== 签名回填(例外 A,ADR 0077 §2.1)===")
        logger.info("APK: ${apk.toAbsolutePath()}")
        logger.info("keystore: ${keystore.toAbsolutePath()}")
        logger.info("服务器: $serverUrl")

        val apkFile = apk.toFile()
        val keystoreFile = keystore.toFile()
        val outPath = output?.toFile()
            ?: File(apkFile.parentFile, apkFile.nameWithoutExtension + "-resigned.apk")

        // 构建 multipart/form-data 请求
        val boundary = "xcj-resign-boundary-${System.currentTimeMillis()}"
        val multipartBody = buildMultipartBody(boundary, apkFile, keystoreFile)

        val url = "$serverUrl/v1/audit/resign"
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

        logger.info("上传 APK + keystore,后端三重校验 + 重签中...")
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != 200 && response.statusCode() != 201) {
            logger.error("重签失败: HTTP ${response.statusCode()}")
            logger.error("响应: ${response.body().take(500)}")
            throw RuntimeException("AUDIT_RESIGN_FAILED: HTTP ${response.statusCode()}")
        }

        // 解析响应 JSON,提取 resignedApkBase64
        val body = response.body()
        val base64Regex = Regex("\"resignedApkBase64\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
        val base64Match = base64Regex.find(body)
            ?: throw RuntimeException("响应中未找到 resignedApkBase64 字段: ${body.take(200)}")
        val base64Data = base64Match.groupValues[1]
            .replace("\\n", "")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")

        val resignedApk = Base64.getDecoder().decode(base64Data)
        outPath.writeBytes(resignedApk)

        // 提取 newHash / oldHash
        val newHashRegex = Regex("\"newHash\"\\s*:\\s*\"([0-9a-fA-F]+)\"")
        val oldHashRegex = Regex("\"oldHash\"\\s*:\\s*\"([0-9a-fA-F]+)\"")
        val newHashMatch = newHashRegex.find(body)
        val oldHashMatch = oldHashRegex.find(body)

        logger.info("=== 重签完成 ===")
        logger.info("输出: ${outPath.absolutePath}")
        logger.info("大小: ${resignedApk.size / 1024} KB")
        oldHashMatch?.let { logger.info("原 hash: ${it.groupValues[1]}") }
        newHashMatch?.let { logger.info("新 hash: ${it.groupValues[1]}(已自动入白名单)") }
    }

    /**
     * 构建 multipart/form-data 请求体
     */
    private fun buildMultipartBody(boundary: String, apkFile: File, keystoreFile: File): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(baos)

        // apk 字段
        dos.writeBytes("--$boundary\r\n")
        dos.writeBytes("Content-Disposition: form-data; name=\"apk\"; filename=\"${apkFile.name}\"\r\n")
        dos.writeBytes("Content-Type: application/vnd.android.package-archive\r\n")
        dos.writeBytes("\r\n")
        dos.write(apkFile.readBytes())
        dos.writeBytes("\r\n")

        // keystore 字段
        dos.writeBytes("--$boundary\r\n")
        dos.writeBytes("Content-Disposition: form-data; name=\"keystore\"; filename=\"${keystoreFile.name}\"\r\n")
        dos.writeBytes("Content-Type: application/octet-stream\r\n")
        dos.writeBytes("\r\n")
        dos.write(keystoreFile.readBytes())
        dos.writeBytes("\r\n")

        // 凭证字段
        fun writeField(name: String, value: String) {
            dos.writeBytes("--$boundary\r\n")
            dos.writeBytes("Content-Disposition: form-data; name=\"$name\"\r\n")
            dos.writeBytes("\r\n")
            dos.writeBytes(value)
            dos.writeBytes("\r\n")
        }
        writeField("keystorePassword", ksPass)
        writeField("keyAlias", keyAlias)
        writeField("keyPassword", keyPass)
        writeField("originalName", apkFile.name)

        dos.writeBytes("--$boundary--\r\n")
        dos.flush()
        return baos.toByteArray()
    }
}

/**
 * audit bangcle-eula 子命令:查看/接受梆梆加固自检 EULA(ADR 0078 锁 B)
 *
 * 用法:
 *  injector audit bangcle-eula --server-url ... --token ... --accept
 *  injector audit bangcle-eula --server-url ... --token ...   (仅查看)
 */
class BangcleEulaCommand : CliktCommand(
    name = "bangcle-eula",
    help = "查看/接受梆梆加固自检 EULA(ADR 0078 锁 B 前置)"
) {
    private val serverUrl by option("--server-url", help = "SaaS 服务器 URL")
        .required()

    private val token by option("--token", help = "管理员 JWT")
        .required()

    private val accept by option(
        "--accept",
        help = "接受当前版本 EULA(不加此参数则只查看 EULA 文本)"
    ).flag()

    override fun run() {
        logger.info("=== 梆梆加固自检 EULA(ADR 0078 锁 B)===")

        val client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build()

        // 1. GET /v1/audit/eula 获取 EULA
        val getUrl = "$serverUrl/v1/audit/eula"
        val getRequest = HttpRequest.newBuilder()
            .uri(URI.create(getUrl))
            .timeout(Duration.ofSeconds(15))
            .GET()
            .header("Authorization", "Bearer $token")
            .build()

        val getResponse = client.send(getRequest, HttpResponse.BodyHandlers.ofString())
        if (getResponse.statusCode() != 200) {
            throw RuntimeException("获取 EULA 失败: HTTP ${getResponse.statusCode()}: ${getResponse.body().take(300)}")
        }

        val eulaBody = getResponse.body()
        val versionRegex = Regex("\"version\"\\s*:\\s*\"([^\"]+)\"")
        val versionMatch = versionRegex.find(eulaBody)
            ?: throw RuntimeException("EULA 响应未含 version 字段: ${eulaBody.take(300)}")
        val version = versionMatch.groupValues[1]
        val effectiveDateRegex = Regex("\"effectiveDate\"\\s*:\\s*\"([^\"]+)\"")
        val effectiveDateMatch = effectiveDateRegex.find(eulaBody)
        val effectiveDate = if (effectiveDateMatch != null) effectiveDateMatch.groupValues[1] else "(unknown)"

        logger.info("EULA 版本: $version")
        logger.info("生效日期: $effectiveDate")
        println()
        println(eulaBody)

        if (!accept) {
            logger.info("---")
            logger.info("如需接受,请加 --accept 参数")
            return
        }

        // 2. POST /v1/audit/eula/accept 接受 EULA
        val postUrl = "$serverUrl/v1/audit/eula/accept"
        val postBody = """{"version":"$version"}"""
        val postRequest = HttpRequest.newBuilder()
            .uri(URI.create(postUrl))
            .timeout(Duration.ofSeconds(15))
            .POST(HttpRequest.BodyPublishers.ofString(postBody))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer $token")
            .build()

        val postResponse = client.send(postRequest, HttpResponse.BodyHandlers.ofString())
        if (postResponse.statusCode() != 200 && postResponse.statusCode() != 201) {
            throw RuntimeException("接受 EULA 失败: HTTP ${postResponse.statusCode()}: ${postResponse.body().take(300)}")
        }

        logger.info("=== EULA 已接受 ===")
        logger.info("版本: $version")
        logger.info("现在可以使用 injector audit analyze --hardener bangcle 执行梆梆自检")
    }
}
