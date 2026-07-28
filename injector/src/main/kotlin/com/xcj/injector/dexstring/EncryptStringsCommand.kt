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
 * 管线: dexlib2 3.0.7 修改 DEX → 写出 → 精确 binary patch debug_info parameter_name。
 * dexlib2 3.0.7 writer 重排 string table 后 debug_info_item 中 parameter_name
 * 索引失效。用等长 ULEB128 替换为 0(NO_INDEX),保持编码长度不变。
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
                        val newEntry = ZipEntry(entry.name)
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
        val opcodes = Opcodes.forDexVersion(dexVersion)
        val dexFile = DexBackedDexFile(opcodes, dexBytes)
        val modifiedClasses = encryptor.processDex(dexFile)

        val outputDex = com.android.tools.smali.dexlib2.immutable.ImmutableDexFile(
            opcodes, modifiedClasses
        )

        val tmpFile = File.createTempFile("t4_dex", ".dex")
        try {
            DexFileFactory.writeDexFile(tmpFile.absolutePath, outputDex)
            val rawDex = tmpFile.readBytes()
            logger.info("  dexlib2 3.0.7 输出: ${rawDex.size} bytes (保留原始 debug_info)")
            return rawDex
        } finally {
            tmpFile.delete()
        }
    }

    // ========== 精确 binary patch: 等长 ULEB128 替换 parameter_name ==========

    /**
     * 遍历 DEX 中所有 debug_info_item,将每个 parameter_name 等长替换为 0。
     *
     * 等长替换原理:
     *   1 字节 ULEB128 (值<128) → 写 0x00
     *   2 字节 ULEB128 → 写 0x80 0x00 (等长, 值=0)
     *   3 字节 ULEB128 → 写 0x80 0x80 0x00 (等长, 值=0)
     *   N 字节 ULEB128 → 写 (N-1) 个 0x80 + 1 个 0x00
     *
     * 这样编码长度不变,后续字节偏移不受影响,值变为 0(NO_INDEX)。
     *
     * @return Pair(patched_dex, patch_count)
     */
    private fun patchParameterNames(dex: ByteArray): Pair<ByteArray, Int> {
        val result = dex.copyOf()
        val buf = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN)

        val stringIdsSize = buf.getInt(56)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        var patchCount = 0

        for (i in 0 until classDefsSize) {
            val classDefOff = classDefsOff + i * 32
            val classDataOff = buf.getInt(classDefOff + 24)
            if (classDataOff == 0) continue

            var pos = classDataOff
            val (staticFieldsSize, p1) = readUleb128(result, pos); pos = p1
            val (instanceFieldsSize, p2) = readUleb128(result, pos); pos = p2
            val (directMethodsSize, p3) = readUleb128(result, pos); pos = p3
            val (virtualMethodsSize, p4) = readUleb128(result, pos); pos = p4

            // Skip fields
            pos = skipEncodedFields(result, pos, staticFieldsSize + instanceFieldsSize)

            // Process methods (direct + virtual)
            for (methodIdx in 0 until (directMethodsSize + virtualMethodsSize)) {
                val (_, pa) = readUleb128(result, pos); pos = pa  // method_idx_diff
                val (_, pb) = readUleb128(result, pos); pos = pb  // access_flags
                val (codeOff, pc) = readUleb128(result, pos); pos = pc
                if (codeOff == 0) continue

                // code_item.debug_info_off at codeOff + 8
                val debugInfoOff = buf.getInt(codeOff + 8)
                if (debugInfoOff == 0) continue

                // Parse debug_info_item header
                var dpos = debugInfoOff
                val (_, d1) = readUleb128(result, dpos); dpos = d1  // line_start
                val (paramsSize, d2) = readUleb128(result, dpos); dpos = d2

                // Patch each parameter_name (ULEB128 → equal-length zero)
                for (pi in 0 until paramsSize) {
                    val nameStart = dpos
                    val (nameVal, nameEnd) = readUleb128(result, dpos)
                    dpos = nameEnd

                    if (nameVal != 0) {
                        val strIdx = nameVal - 1  // parameter_name is 1-based (0 = NO_INDEX)
                        if (strIdx >= stringIdsSize) {
                            // Bad index! Patch to zero with equal length
                            val encLen = nameEnd - nameStart
                            writeEqualLengthZeroUleb128(result, nameStart, encLen)
                            patchCount++
                        }
                    }
                }

                // We don't need to patch the rest of debug_info (opcodes + data)
                // because the error is specifically about parameter_name indices
            }
        }

        // 重算 DEX header checksum (adler32 of bytes 12..end)
        val adler = Adler32()
        adler.update(result, 12, result.size - 12)
        val checksum = adler.value.toInt()
        result[8] = (checksum and 0xFF).toByte()
        result[9] = ((checksum shr 8) and 0xFF).toByte()
        result[10] = ((checksum shr 16) and 0xFF).toByte()
        result[11] = ((checksum shr 24) and 0xFF).toByte()

        // 重算 DEX header signature (SHA-1 of bytes 32..end)
        val sha1 = MessageDigest.getInstance("SHA-1")
        sha1.update(result, 32, result.size - 32)
        val sig = sha1.digest()
        System.arraycopy(sig, 0, result, 12, 20)

        return Pair(result, patchCount)
    }

    /**
     * 写等长的零值 ULEB128。
     * encLen=1 → [0x00]
     * encLen=2 → [0x80, 0x00]
     * encLen=3 → [0x80, 0x80, 0x00]
     * ...
     */
    private fun writeEqualLengthZeroUleb128(data: ByteArray, offset: Int, encLen: Int) {
        for (i in 0 until encLen - 1) {
            data[offset + i] = 0x80.toByte()  // continuation bit set, value bits = 0
        }
        data[offset + encLen - 1] = 0x00  // final byte: no continuation, value = 0
    }

    private fun skipEncodedFields(data: ByteArray, startPos: Int, count: Int): Int {
        var pos = startPos
        repeat(count) {
            val (_, pa) = readUleb128(data, pos); pos = pa  // field_idx_diff
            val (_, pb) = readUleb128(data, pos); pos = pb  // access_flags
        }
        return pos
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
