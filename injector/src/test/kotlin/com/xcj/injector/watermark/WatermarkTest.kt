package com.xcj.injector.watermark

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipFile

/**
 * Watermark 单元测试
 *
 * 测试 embed + embedEncrypted 方法:
 *  - 创建临时 APK(空 zip)
 *  - 调 embed/embedEncrypted 写入水印
 *  - 验证 META-INF/xcj-watermark.txt 或 META-INF/xcj-watermark.enc.txt 存在
 *  - 验证水印内容
 */
class WatermarkTest {

    @Test
    fun `embed 应写入 META-INF_xcj-watermark_txt`() {
        val tempApk = File.createTempFile("test", ".apk")
        tempApk.deleteOnExit()
        net.lingala.zip4j.ZipFile(tempApk).close()

        @Suppress("DEPRECATION")
        val watermark = Watermark()
        @Suppress("DEPRECATION")
        watermark.embed(tempApk, "test-developer-123")

        val zipFile = ZipFile(tempApk)
        val entry = zipFile.getEntry("META-INF/xcj-watermark.txt")
        assertTrue("水印文件应存在", entry != null)

        val content = zipFile.getInputStream(entry).bufferedReader().readText()
        assertTrue("应含 version", content.contains("version:"))
        assertTrue("应含 watermarkId", content.contains("watermarkId: test-developer-123"))
        assertTrue("应含 timestamp", content.contains("timestamp:"))

        zipFile.close()
        tempApk.delete()
    }

    @Test
    fun `embed 应写入正确的水印 ID`() {
        val tempApk = File.createTempFile("test", ".apk")
        tempApk.deleteOnExit()
        net.lingala.zip4j.ZipFile(tempApk).close()

        @Suppress("DEPRECATION")
        val watermark = Watermark()
        @Suppress("DEPRECATION")
        watermark.embed(tempApk, "dev-456")

        val zipFile = ZipFile(tempApk)
        val entry = zipFile.getEntry("META-INF/xcj-watermark.txt")
        val content = zipFile.getInputStream(entry).bufferedReader().readText()

        assertTrue("应含 dev-456", content.contains("dev-456"))

        zipFile.close()
        tempApk.delete()
    }

    @Test
    fun `InjectorConstants_VERSION 应为 0_2_0`() {
        assertEquals("0.2.0", InjectorConstants.VERSION)
    }

    @Test
    fun `embedEncrypted 应写入 META-INF_xcj-watermark_enc_txt`() {
        val tempApk = File.createTempFile("test", ".apk")
        tempApk.deleteOnExit()
        net.lingala.zip4j.ZipFile(tempApk).close()

        val base64Watermark = "eyJpdiI6InRlc3QifQ=="

        val watermark = Watermark()
        watermark.embedEncrypted(tempApk, base64Watermark)

        val zipFile = ZipFile(tempApk)
        val entry = zipFile.getEntry("META-INF/xcj-watermark.enc.txt")
        assertTrue("加密水印文件应存在", entry != null)

        val content = zipFile.getInputStream(entry).bufferedReader().readText()
        assertEquals("应写入 base64 密文", base64Watermark, content)

        zipFile.close()
        tempApk.delete()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `embedEncrypted 空 base64 应抛异常`() {
        val tempApk = File.createTempFile("test", ".apk")
        tempApk.deleteOnExit()
        net.lingala.zip4j.ZipFile(tempApk).close()

        val watermark = Watermark()
        watermark.embedEncrypted(tempApk, "")
    }
}
