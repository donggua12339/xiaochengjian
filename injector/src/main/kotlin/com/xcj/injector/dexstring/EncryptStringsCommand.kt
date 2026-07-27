package com.xcj.injector.dexstring

import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.DexFile
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import org.slf4j.LoggerFactory
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * T4 CLI 命令:对 APK 中的 DEX 字符串加密。
 *
 * 用法: xcj-injector encrypt-strings --apk input.apk --output output.apk
 *
 * 产出:
 *   - output.apk: DEX 中 const-string 已替换为 native 解密调用
 *   - t4_str_key.h: native 解密密钥头文件(写入 defender-sdk/src/main/cpp/)
 *   - XcjEncStringTable 类: 注入到 DEX(持有加密数据)
 */
class EncryptStringsCommand : CliktCommand(
    name = "encrypt-strings",
    help = "T4 DEX 字符串加密(ADR 0090):替换 const-string 为 native 解密调用"
) {
    private val apkPath by option("--apk", help = "输入 APK 路径").required()
    private val outputPath by option("--output", help = "输出 APK 路径").required()
    private val keyOutput by option("--key-header", help = "密钥头文件输出路径(默认 t4_str_key.h)")

    private val logger = LoggerFactory.getLogger(EncryptStringsCommand::class.java)

    override fun run() {
        val apkFile = File(apkPath)
        require(apkFile.exists()) { "APK 不存在: $apkPath" }

        val key = DexStringEncryptor.generateKey()
        val encryptor = DexStringEncryptor(key)

        logger.info("T4 DEX 字符串加密开始: $apkPath")

        val outFile = File(outputPath)
        val keyHeaderPath = keyOutput ?: "t4_str_key.h"

        // 处理 APK(zip 级别遍历,只改 classes*.dex)
        ZipFile(apkFile).use { zip ->
            ZipOutputStream(outFile.outputStream()).use { zos ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val data = zip.getInputStream(entry).readBytes()

                    if (entry.name.matches(Regex("classes\\d*\\.dex"))) {
                        logger.info("处理: ${entry.name} (${data.size} bytes)")
                        val modified = processDexEntry(data, encryptor)
                        val newEntry = ZipEntry(entry.name)
                        zos.putNextEntry(newEntry)
                        zos.write(modified)
                        zos.closeEntry()
                    } else {
                        // 原样复制(保留 STORED 压缩方式,bin 文件不可 DEFLATE)
                        val newEntry = ZipEntry(entry.name)
                        if (entry.method == ZipEntry.STORED) {
                            newEntry.method = ZipEntry.STORED
                            newEntry.size = data.size.toLong()
                            newEntry.compressedSize = data.size.toLong()
                            newEntry.crc = entry.crc
                        }
                        zos.putNextEntry(newEntry)
                        zos.write(data)
                        zos.closeEntry()
                    }
                }
            }
        }

        // 输出密钥头文件
        File(keyHeaderPath).writeText(encryptor.generateKeyHeader())
        logger.info("密钥头文件: $keyHeaderPath")
        logger.info("完成: ${encryptor.getStats()}")
        logger.info("输出: $outputPath")
        logger.info("⚠️  需在 defender-sdk 中编译 t4_str_key.h 并注册 DexStringDecryptor native 方法")
    }

    private fun processDexEntry(dexBytes: ByteArray, encryptor: DexStringEncryptor): ByteArray {
        // 读取用原始版本,写出用 039(dexlib2 3.0.7 的 writer 对 037 有 debug_info 兼容 bug)
        val dexVersion = String(dexBytes, 4, 3).toIntOrNull() ?: 37
        val readOpcodes = Opcodes.forDexVersion(dexVersion)
        val writeOpcodes = Opcodes.forDexVersion(39)
        val dexFile = DexBackedDexFile(readOpcodes, dexBytes)
        val modifiedClasses = encryptor.processDex(dexFile)

        // 写入修改后的 DEX(升级到 dex 039,ART 向下兼容)
        val outputDex = com.android.tools.smali.dexlib2.immutable.ImmutableDexFile(
            writeOpcodes,
            modifiedClasses
        )

        val tmpFile = File.createTempFile("t4_dex", ".dex")
        try {
            DexFileFactory.writeDexFile(tmpFile.absolutePath, outputDex)
            return tmpFile.readBytes()
        } finally {
            tmpFile.delete()
        }
    }
}
