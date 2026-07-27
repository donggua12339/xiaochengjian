package com.xcj.injector.dexstring

import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import org.slf4j.LoggerFactory
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * T4 CLI 命令:对 APK 中的 DEX 字符串加密。
 *
 * 管线: dexlib2 修改 DEX → 写出 → binary-patch 清零所有 debug_info_off。
 * dexlib2 3.0.7 writer 重排 string table 后 debug_info_item 中 parameter_name
 * 索引失效(ART verifier 报 Bad index)。清零 debug_info_off 后 ART 跳过验证。
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

        ZipFile(apkFile).use { zip ->
            ZipOutputStream(outFile.outputStream()).use { zos ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val data = zip.getInputStream(entry).readBytes()

                    if (entry.name.matches(Regex("classes\\d*\\.dex"))) {
                        logger.info("处理: ${entry.name} (${data.size} bytes)")
                        val modified = processDexEntry(data, encryptor)
                        // DEX 必须 STORED(不可 DEFLATE):ART mmap 直读,压缩方式不一致会导致验证失败
                        val newEntry = ZipEntry(entry.name)
                        newEntry.method = ZipEntry.STORED
                        newEntry.size = modified.size.toLong()
                        newEntry.compressedSize = modified.size.toLong()
                        val crc32 = java.util.zip.CRC32()
                        crc32.update(modified)
                        newEntry.crc = crc32.value
                        zos.putNextEntry(newEntry)
                        zos.write(modified)
                        zos.closeEntry()
                    } else {
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

        File(keyHeaderPath).writeText(encryptor.generateKeyHeader())
        logger.info("密钥头文件: $keyHeaderPath")
        logger.info("完成: ${encryptor.getStats()}")
        logger.info("输出: $outputPath")
    }

    private fun processDexEntry(dexBytes: ByteArray, encryptor: DexStringEncryptor): ByteArray {
        val dexVersion = String(dexBytes, 4, 3).toIntOrNull() ?: 37
        val readOpcodes = Opcodes.forDexVersion(dexVersion)
        val writeOpcodes = Opcodes.forDexVersion(dexVersion)  // 保持原始版本
        val dexFile = DexBackedDexFile(readOpcodes, dexBytes)
        val modifiedClasses = encryptor.processDex(dexFile)

        val outputDex = com.android.tools.smali.dexlib2.immutable.ImmutableDexFile(
            writeOpcodes, modifiedClasses
        )

        val tmpFile = File.createTempFile("t4_dex", ".dex")
        try {
            DexFileFactory.writeDexFile(tmpFile.absolutePath, outputDex)
            val rawDex = tmpFile.readBytes()
            // 后处理:清零所有 code_item 的 debug_info_off
            patchDebugInfoOff(rawDex)
            logger.info("  debug_info_off 已清零(${countCodeItems(rawDex)} 个 code_item)")
            return rawDex
        } finally {
            tmpFile.delete()
        }
    }

    // ========== DEX binary patch: 清零所有 debug_info_off ==========

    /**
     * 遍历 DEX 中所有 code_item,将 debug_info_off 设为 0。
     * ART verifier 看到 debug_info_off=0 时跳过 debug info 验证。
     */
    private fun patchDebugInfoOff(dex: ByteArray) {
        val buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)

        // DEX header: class_defs_size at offset 96, class_defs_off at offset 100
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        for (i in 0 until classDefsSize) {
            val classDefOff = classDefsOff + i * 32
            val classDataOff = buf.getInt(classDefOff + 24)
            if (classDataOff == 0) continue

            var pos = classDataOff
            val (staticFieldsSize, p1) = readUleb128(dex, pos); pos = p1
            val (instanceFieldsSize, p2) = readUleb128(dex, pos); pos = p2
            val (directMethodsSize, p3) = readUleb128(dex, pos); pos = p3
            val (virtualMethodsSize, p4) = readUleb128(dex, pos); pos = p4

            repeat(staticFieldsSize) {
                val (_, pa) = readUleb128(dex, pos); pos = pa
                val (_, pb) = readUleb128(dex, pos); pos = pb
            }
            repeat(instanceFieldsSize) {
                val (_, pa) = readUleb128(dex, pos); pos = pa
                val (_, pb) = readUleb128(dex, pos); pos = pb
            }
            repeat(directMethodsSize) {
                val (_, pa) = readUleb128(dex, pos); pos = pa
                val (_, pb) = readUleb128(dex, pos); pos = pb
                val (codeOff, pc) = readUleb128(dex, pos); pos = pc
                if (codeOff != 0) zeroDebugInfoOff(dex, codeOff)
            }
            repeat(virtualMethodsSize) {
                val (_, pa) = readUleb128(dex, pos); pos = pa
                val (_, pb) = readUleb128(dex, pos); pos = pb
                val (codeOff, pc) = readUleb128(dex, pos); pos = pc
                if (codeOff != 0) zeroDebugInfoOff(dex, codeOff)
            }
        }

        // 重算 SHA-1 signature(bytes[32..end]) + Adler32 checksum(bytes[12..end])
        val md = MessageDigest.getInstance("SHA-1")
        md.update(dex, 32, dex.size - 32)
        val sha1 = md.digest()
        System.arraycopy(sha1, 0, dex, 12, 20)
        val adler = Adler32()
        adler.update(dex, 12, dex.size - 12)
        val checksum = adler.value.toInt()
        dex[8] = (checksum and 0xFF).toByte()
        dex[9] = ((checksum shr 8) and 0xFF).toByte()
        dex[10] = ((checksum shr 16) and 0xFF).toByte()
        dex[11] = ((checksum shr 24) and 0xFF).toByte()
    }

    private fun zeroDebugInfoOff(dex: ByteArray, codeOff: Int) {
        dex[codeOff + 8] = 0; dex[codeOff + 9] = 0
        dex[codeOff + 10] = 0; dex[codeOff + 11] = 0
    }

    /** Count code_items for logging */
    private fun countCodeItems(dex: ByteArray): Int {
        val buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)
        var count = 0
        for (i in 0 until classDefsSize) {
            val classDataOff = buf.getInt(classDefsOff + i * 32 + 24)
            if (classDataOff == 0) continue
            var pos = classDataOff
            val (sfs, p1) = readUleb128(dex, pos); pos = p1
            val (ifs, p2) = readUleb128(dex, pos); pos = p2
            val (dms, p3) = readUleb128(dex, pos); pos = p3
            val (vms, p4) = readUleb128(dex, pos); pos = p4
            pos = skipFields(dex, pos, sfs + ifs)
            count += countMethods(dex, pos, dms).second
            // skip to virtual methods
            val (_, afterDirect) = skipMethods(dex, pos, dms)
            count += countMethods(dex, afterDirect, vms).second
        }
        return count
    }

    private fun skipFields(dex: ByteArray, startPos: Int, count: Int): Int {
        var pos = startPos
        repeat(count) {
            val (_, pa) = readUleb128(dex, pos); pos = pa
            val (_, pb) = readUleb128(dex, pos); pos = pb
        }
        return pos
    }

    private fun countMethods(dex: ByteArray, startPos: Int, count: Int): Pair<Int, Int> {
        var pos = startPos
        var withCode = 0
        repeat(count) {
            val (_, pa) = readUleb128(dex, pos); pos = pa
            val (_, pb) = readUleb128(dex, pos); pos = pb
            val (codeOff, pc) = readUleb128(dex, pos); pos = pc
            if (codeOff != 0) withCode++
        }
        return Pair(pos, withCode)
    }

    private fun skipMethods(dex: ByteArray, startPos: Int, count: Int): Pair<Int, Int> {
        var pos = startPos
        repeat(count) {
            val (_, pa) = readUleb128(dex, pos); pos = pa
            val (_, pb) = readUleb128(dex, pos); pos = pb
            val (_, pc) = readUleb128(dex, pos); pos = pc
        }
        return Pair(pos, 0)
    }

    /** Read ULEB128 from byte array, return (value, new_position) */
    private fun readUleb128(data: ByteArray, offset: Int): Pair<Int, Int> {
        var result = 0
        var shift = 0
        var pos = offset
        while (true) {
            val b = data[pos].toInt() and 0xFF
            pos++
            result = result or ((b and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
        }
        return Pair(result, pos)
    }
}
