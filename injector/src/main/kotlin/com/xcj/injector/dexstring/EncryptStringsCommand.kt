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
 * 管线: dexlib2 3.0.7 修改 DEX → 写出 → binary patch debug_info parameter_name。
 * dexlib2 3.0.7 writer 重排 string table 后 debug_info_item 中 parameter_name
 * 索引可能越界。patchParameterNames 用等长 ULEB128 替换为 0(NO_INDEX),
 * 保持编码长度不变,再重算 adler32 + SHA-1。
 */
class EncryptStringsCommand :
    CliktCommand(
        name = "encrypt-strings",
        help = "T4 DEX 字符串加密(ADR 0090):替换 const-string 为 native 解密调用",
    ) {
    private val apkPath by option("--apk", help = "输入 APK 路径").required()
    private val outputPath by option("--output", help = "输出 APK 路径").required()
    private val keyOutput by option("--key-header", help = "密钥头文件输出路径(默认 t4_str_key.h)")
    private val keyHex by option(
        "--key-hex",
        help = "使用指定的 16 字节 hex 密钥(管线复用预编译 SO 的密钥);缺省随机生成",
    )

    private val logger = LoggerFactory.getLogger(EncryptStringsCommand::class.java)

    /** 单个 dex 的处理中间结果 */
    private class DexWork(
        val opcodes: Opcodes,
        val classes: MutableList<com.android.tools.smali.dexlib2.iface.ClassDef>,
    )

    override fun run() {
        val apkFile = File(apkPath)
        require(apkFile.exists()) { "APK 不存在: $apkPath" }

        val key = keyHex?.let { parseKeyHex(it) } ?: DexStringEncryptor.generateKey()
        val encryptor = DexStringEncryptor(key)

        logger.info("T4 DEX 字符串加密开始: $apkPath")

        val outFile = File(outputPath)
        val keyHeaderPath = keyOutput ?: "t4_str_key.h"

        /* Pass 1: 处理全部 dex,记录被修改的(表类含全部 dex 累计的字符串,
         * 必须在所有 dex 处理完后才能注入,否则漏掉后续 dex 的条目) */
        val dexWorks = LinkedHashMap<String, DexWork>()
        ZipFile(apkFile).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (!entry.name.matches(Regex("classes\\d*\\.dex"))) continue
                val data = zip.getInputStream(entry).readBytes()
                logger.info("处理: ${entry.name} (${data.size} bytes)")
                val dexVersion = String(data, 4, 3).toIntOrNull() ?: 37
                val opcodes = Opcodes.forDexVersion(dexVersion)
                val result = encryptor.processDex(DexBackedDexFile(opcodes, data))
                if (result.modified) {
                    dexWorks[entry.name] = DexWork(opcodes, result.classes.toMutableList())
                } else {
                    logger.info("  无可加密字符串,保留原 dex")
                }
            }
        }

        if (dexWorks.isEmpty()) {
            logger.warn("APK 中无可加密字符串,原样复制")
            apkFile.copyTo(outFile, overwrite = true)
            return
        }

        // XcjEncStringTable 注入最后一个被修改的 dex(表含全部字符串)
        val lastName = dexWorks.keys.last()
        dexWorks[lastName]!!.classes.add(encryptor.buildEncStringTableClassDef())
        logger.info("注入 XcjEncStringTable → $lastName (${encryptor.getStats()})")

        // Pass 2: 写出 zip(被修改 dex 重建,其余条目原样保留)
        ZipFile(apkFile).use { zip ->
            ZipOutputStream(outFile.outputStream()).use { zos ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val newEntry = ZipEntry(entry.name)
                    val work = dexWorks[entry.name]
                    if (work != null) {
                        val dexBytes =
                            writeDex(
                                com.android.tools.smali.dexlib2.immutable.ImmutableDexFile(
                                    work.opcodes,
                                    work.classes,
                                ),
                            )
                        zos.putNextEntry(newEntry)
                        zos.write(dexBytes)
                        zos.closeEntry()
                    } else {
                        val data = zip.getInputStream(entry).readBytes()
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

    /** 解析 --key-hex(32 个 hex 字符 = 16 字节) */
    private fun parseKeyHex(hex: String): ByteArray {
        val clean = hex.trim()
        require(clean.length == 32 && clean.all { it in "0123456789abcdefABCDEF" }) {
            "--key-hex 必须是 16 字节 hex(32 个 hex 字符)"
        }
        return clean.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun writeDex(outputDex: com.android.tools.smali.dexlib2.immutable.ImmutableDexFile): ByteArray {
        val tmpFile = File.createTempFile("t4_dex", ".dex")
        try {
            DexFileFactory.writeDexFile(tmpFile.absolutePath, outputDex)
            val rawDex = tmpFile.readBytes()
            // dexlib2 3.0.7 writer 重排 string table → debug_info parameter_name 索引越界
            // binary patch: 等长 ULEB128 替换为 0(NO_INDEX),保持偏移不变
            val (patched, count) = patchParameterNames(rawDex)
            if (count > 0) {
                logger.info("  binary patch: 修复 $count 个越界 parameter_name 索引")
            }
            logger.info("  dexlib2 输出: ${patched.size} bytes")
            return patched
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
    internal fun patchParameterNames(dex: ByteArray): Pair<ByteArray, Int> {
        val result = dex.copyOf()
        val buf = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN)

        val stringIdsSize = buf.getInt(56)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        var patchCount = 0

        for (i in 0 until classDefsSize) {
            val classDefOff = classDefsOff + i * 32
            val classDataOff = buf.getInt(classDefOff + 24)
            if (classDataOff == 0 || classDataOff >= result.size) continue

            var pos = classDataOff
            val (staticFieldsSize, p1) = readUleb128(result, pos)
            pos = p1
            val (instanceFieldsSize, p2) = readUleb128(result, pos)
            pos = p2
            val (directMethodsSize, p3) = readUleb128(result, pos)
            pos = p3
            val (virtualMethodsSize, p4) = readUleb128(result, pos)
            pos = p4

            // Skip fields
            pos = skipEncodedFields(result, pos, (staticFieldsSize + instanceFieldsSize).toInt())

            // Process methods (direct + virtual)
            for (methodIdx in 0 until (directMethodsSize + virtualMethodsSize).toInt()) {
                val (_, pa) = readUleb128(result, pos)
                pos = pa // method_idx_diff
                val (_, pb) = readUleb128(result, pos)
                pos = pb // access_flags
                val (codeOff, pc) = readUleb128(result, pos)
                pos = pc
                if (codeOff == 0L || codeOff >= result.size) continue

                // code_item.debug_info_off at codeOff + 8
                val debugInfoOff = buf.getInt(codeOff.toInt() + 8)
                if (debugInfoOff == 0 || debugInfoOff < 0 || debugInfoOff >= result.size) continue

                // Parse debug_info_item header
                var dpos = debugInfoOff
                val (_, d1) = readUleb128(result, dpos)
                dpos = d1 // line_start
                val (paramsSize, d2) = readUleb128(result, dpos)
                dpos = d2

                // Patch each parameter_name (ULEB128 → equal-length zero)
                // 结构化判定,不依赖数值比较:损坏的 name 字段可达 10+ 字节,
                // 任何定长整数解码都会溢出成负数绕过 >= 判断。
                // 改为扫终止字节(最高位为 0)定编码长度,合法 = 长度 ≤5 且值在界内。
                if (paramsSize > 0xFFFFL) continue // 参数数量本身损坏,跳过本方法
                for (pi in 0 until paramsSize.toInt()) {
                    val nameStart = dpos
                    var nameEnd = nameStart
                    while (nameEnd < result.size &&
                        (result[nameEnd].toInt() and 0x80) != 0
                    ) {
                        nameEnd++
                    }
                    if (nameEnd >= result.size) break // 无终止字节,数据损坏到文件尾
                    nameEnd++ // 含终止字节
                    dpos = nameEnd
                    val encLen = nameEnd - nameStart

                    val (nameVal, _) = readUleb128(result, nameStart)
                    val valid =
                        encLen <= 5 &&
                            nameVal >= 0L &&
                            (nameVal == 0L || nameVal - 1 < stringIdsSize.toLong())
                    if (!valid) {
                        writeEqualLengthZeroUleb128(result, nameStart, encLen)
                        patchCount++
                    }
                }

                // We don't need to patch the rest of debug_info (opcodes + data)
                // because the error is specifically about parameter_name indices
            }
        }

        // 重算 DEX header signature (SHA-1 of bytes 32..end)
        // 必须先写 signature 再算 checksum,因为 checksum 覆盖 bytes 12..end(含 signature)
        val sha1 = MessageDigest.getInstance("SHA-1")
        sha1.update(result, 32, result.size - 32)
        val sig = sha1.digest()
        System.arraycopy(sig, 0, result, 12, 20)

        // 重算 DEX header checksum (adler32 of bytes 12..end)
        val adler = Adler32()
        adler.update(result, 12, result.size - 12)
        val checksum = adler.value.toInt()
        result[8] = (checksum and 0xFF).toByte()
        result[9] = ((checksum shr 8) and 0xFF).toByte()
        result[10] = ((checksum shr 16) and 0xFF).toByte()
        result[11] = ((checksum shr 24) and 0xFF).toByte()

        return Pair(result, patchCount)
    }

    /**
     * 写等长的零值 ULEB128。
     * encLen=1 → [0x00]
     * encLen=2 → [0x80, 0x00]
     * encLen=3 → [0x80, 0x80, 0x00]
     * ...
     */
    internal fun writeEqualLengthZeroUleb128(
        data: ByteArray,
        offset: Int,
        encLen: Int,
    ) {
        for (i in 0 until encLen - 1) {
            data[offset + i] = 0x80.toByte() // continuation bit set, value bits = 0
        }
        data[offset + encLen - 1] = 0x00 // final byte: no continuation, value = 0
    }

    internal fun skipEncodedFields(
        data: ByteArray,
        startPos: Int,
        count: Int,
    ): Int {
        var pos = startPos
        repeat(count) {
            val (_, pa) = readUleb128(data, pos)
            pos = pa // field_idx_diff
            val (_, pb) = readUleb128(data, pos)
            pos = pb // access_flags
        }
        return pos
    }

    /** Read ULEB128 from byte array, return (value, new_position).
     * 必须用 Long:越界的 parameter_name 可达 5 字节(>Int),Int 溢出变负
     * 会绕过 >= stringIdsSize 判断导致漏 patch(ART 按任意精度读,验证必炸)。 */
    internal fun readUleb128(
        data: ByteArray,
        offset: Int,
    ): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var pos = offset
        while (pos < data.size) {
            val b = data[pos].toInt() and 0xFF
            pos++
            result = result or (((b and 0x7F).toLong()) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
        }
        return Pair(result, pos)
    }
}
