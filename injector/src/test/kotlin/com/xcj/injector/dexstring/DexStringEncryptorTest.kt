package com.xcj.injector.dexstring

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.debug.ImmutableLineNumber
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32

/**
 * T4 DEX 字符串加密 + binary patcher 单元测试。
 *
 * 覆盖:
 *  - readUleb128 / writeEqualLengthZeroUleb128 基础工具
 *  - patchParameterNames 修复越界 parameter_name 索引
 *  - DexStringEncryptor.processDex 加密 const-string + 注入 XcjEncStringTable
 */
class DexStringEncryptorTest {
    private val cmd = EncryptStringsCommand()

    // ===== readUleb128 =====

    @Test
    fun `readUleb128 零值`() {
        val (value, pos) = cmd.readUleb128(byteArrayOf(0x00), 0)
        assertEquals(0, value)
        assertEquals(1, pos)
    }

    @Test
    fun `readUleb128 单字节`() {
        val (value, pos) = cmd.readUleb128(byteArrayOf(0x05), 0)
        assertEquals(5, value)
        assertEquals(1, pos)
    }

    @Test
    fun `readUleb128 双字节 128`() {
        // 128 → ULEB128: 0x80 0x01
        val (value, pos) = cmd.readUleb128(byteArrayOf(0x80.toByte(), 0x01), 0)
        assertEquals(128, value)
        assertEquals(2, pos)
    }

    @Test
    fun `readUleb128 三字节 16384`() {
        // 16384 → ULEB128: 0x80 0x80 0x01
        val data = byteArrayOf(0x80.toByte(), 0x80.toByte(), 0x01)
        val (value, pos) = cmd.readUleb128(data, 0)
        assertEquals(16384, value)
        assertEquals(3, pos)
    }

    @Test
    fun `readUleb128 带偏移`() {
        val data = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0x0A)
        val (value, pos) = cmd.readUleb128(data, 2)
        assertEquals(10, value)
        assertEquals(3, pos)
    }

    // ===== writeEqualLengthZeroUleb128 =====

    @Test
    fun `writeEqualLengthZero 单字节`() {
        val data = byteArrayOf(0x05)
        cmd.writeEqualLengthZeroUleb128(data, 0, 1)
        assertEquals(0x00, data[0].toInt() and 0xFF)
        val (value, _) = cmd.readUleb128(data, 0)
        assertEquals(0, value)
    }

    @Test
    fun `writeEqualLengthZero 双字节保持长度`() {
        val data = byteArrayOf(0x85.toByte(), 0x01)
        cmd.writeEqualLengthZeroUleb128(data, 0, 2)
        assertEquals(0x80, data[0].toInt() and 0xFF)
        assertEquals(0x00, data[1].toInt() and 0xFF)
        val (value, pos) = cmd.readUleb128(data, 0)
        assertEquals(0, value)
        assertEquals(2, pos)
    }

    @Test
    fun `writeEqualLengthZero 三字节保持长度`() {
        val data = byteArrayOf(0x85.toByte(), 0x81.toByte(), 0x01)
        cmd.writeEqualLengthZeroUleb128(data, 0, 3)
        assertEquals(0x80, data[0].toInt() and 0xFF)
        assertEquals(0x80, data[1].toInt() and 0xFF)
        assertEquals(0x00, data[2].toInt() and 0xFF)
        val (value, pos) = cmd.readUleb128(data, 0)
        assertEquals(0, value)
        assertEquals(3, pos)
    }

    // ===== patchParameterNames =====

    @Test
    fun `patchParameterNames 修复越界索引并保持 DEX 可解析`() {
        val bytes = writeDexToBytes(buildMinimalDexWithParamNames())
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = buf.getInt(56)

        // 找到第一个非零 parameter_name 并篡改为越界值
        val paramOff = findFirstNonZeroParameterName(bytes)
        if (paramOff == null) {
            // dexlib2 writer 未生成 parameter_name → 验证 patcher 不破坏有效 DEX
            val (patched, _) = cmd.patchParameterNames(bytes)
            val parsed = DexBackedDexFile(Opcodes.forDexVersion(37), patched)
            assertTrue("patcher 不应破坏有效 DEX", parsed.classes.isNotEmpty())
            return
        }

        val corrupted = bytes.copyOf()
        val (origVal, origEnd) = cmd.readUleb128(corrupted, paramOff)
        val encLen = origEnd - paramOff
        // 写入越界值: stringIdsSize + 1(1-based → 索引 stringIdsSize 越界)
        writeUleb128EqualLength(corrupted, paramOff, encLen, stringIdsSize + 1)

        val (patched, count) = cmd.patchParameterNames(corrupted)
        assertTrue("应至少修复 1 个越界索引", count >= 1)

        // 验证被 patch 位置为 0
        val (patchedVal, _) = cmd.readUleb128(patched, paramOff)
        assertEquals("越界索引应替换为 0(NO_INDEX)", 0, patchedVal)

        // 验证编码长度不变
        val (_, patchedEnd) = cmd.readUleb128(patched, paramOff)
        assertEquals("编码长度应不变", encLen, patchedEnd - paramOff)

        // 验证 adler32 checksum
        val adler = Adler32()
        adler.update(patched, 12, patched.size - 12)
        assertEquals(
            "adler32 应正确",
            adler.value.toInt(),
            ByteBuffer.wrap(patched).order(ByteOrder.LITTLE_ENDIAN).getInt(8),
        )

        // 验证 SHA-1 signature
        val sha1 = MessageDigest.getInstance("SHA-1")
        sha1.update(patched, 32, patched.size - 32)
        val expectedSig = sha1.digest()
        val actualSig = patched.copyOfRange(12, 32)
        assertTrue("SHA-1 应正确", expectedSig.contentEquals(actualSig))

        // 验证 dexlib2 可解析
        val parsed = DexBackedDexFile(Opcodes.forDexVersion(37), patched)
        assertTrue("应含至少 1 个 class", parsed.classes.isNotEmpty())
    }

    @Test
    fun `patchParameterNames 正常 DEX 无越界时不破坏`() {
        val bytes = writeDexToBytes(buildMinimalDexWithParamNames())
        val (patched, _) = cmd.patchParameterNames(bytes)

        // 验证 DEX 仍可解析
        val parsed = DexBackedDexFile(Opcodes.forDexVersion(37), patched)
        assertTrue(parsed.classes.isNotEmpty())

        // 验证所有 parameter_name 索引合法
        val buf = ByteBuffer.wrap(patched).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = buf.getInt(56)
        assertAllParameterNamesInRange(patched, stringIdsSize)
    }

    // ===== DexStringEncryptor =====

    @Test
    fun `processDex 应加密 const-string 并注入 XcjEncStringTable`() {
        val key = DexStringEncryptor.generateKey()
        val encryptor = DexStringEncryptor(key)

        val dexBytes = writeDexToBytes(buildDexWithConstString("hello_world_test_string"))
        val dexFile = DexBackedDexFile(Opcodes.forDexVersion(37), dexBytes)
        val result = encryptor.processDex(dexFile)

        assertTrue(
            "应注入 XcjEncStringTable",
            result.any { it.type == "Lcom/xcj/defender/XcjEncStringTable;" },
        )
        assertTrue("应加密至少 1 个字符串", encryptor.getEncryptedTable().isNotEmpty())
    }

    @Test
    fun `processDex 跳过 SDK 命名空间`() {
        val key = DexStringEncryptor.generateKey()
        val encryptor = DexStringEncryptor(key)

        val dexBytes = writeDexToBytes(buildDexWithSdkClass())
        val dexFile = DexBackedDexFile(Opcodes.forDexVersion(37), dexBytes)
        val result = encryptor.processDex(dexFile)

        // SDK 类不应被修改,不应注入 XcjEncStringTable
        assertTrue(
            "SDK 类不应被加密",
            result.none { it.type == "Lcom/xcj/defender/XcjEncStringTable;" },
        )
    }

    @Test
    fun `encryptStrings 端到端写出后 patch 仍可解析`() {
        val key = DexStringEncryptor.generateKey()
        val encryptor = DexStringEncryptor(key)

        val dexBytes = writeDexToBytes(buildDexWithConstStringAndParams("test_encrypt_string"))
        val dexFile = DexBackedDexFile(Opcodes.forDexVersion(37), dexBytes)
        val modified = encryptor.processDex(dexFile)

        val outputDex = ImmutableDexFile(Opcodes.forDexVersion(37), modified)
        val written = writeDexToBytes(outputDex)

        // 经 patchParameterNames 修复后应可解析
        val (patched, _) = cmd.patchParameterNames(written)
        val parsed = DexBackedDexFile(Opcodes.forDexVersion(37), patched)
        assertTrue("加密+patch 后 DEX 应可解析", parsed.classes.isNotEmpty())
    }

    @Test
    fun `generateKeyHeader 应含 C 宏`() {
        val key =
            byteArrayOf(
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x0A,
                0x0B,
                0x0C,
                0x0D,
                0x0E,
                0x0F,
                0x10,
            )
        val encryptor = DexStringEncryptor(key)
        val header = encryptor.generateKeyHeader()

        assertTrue(header.contains("#ifndef T4_STR_KEY_H"))
        assertTrue(header.contains("#define T4_XOR_KEY_LEN 16"))
        assertTrue(header.contains("0x01"))
        assertTrue(header.contains("0x10"))
    }

    // ===== helpers =====

    private fun buildMinimalDexWithParamNames(): ImmutableDexFile {
        val methodImpl =
            ImmutableMethodImplementation(
                3,
                listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
                null,
                listOf(ImmutableLineNumber(0, 42)),
            )
        val method =
            ImmutableMethod(
                "Lcom/test/Hello;",
                "greet",
                listOf(
                    ImmutableMethodParameter("Ljava/lang/String;", null, "name"),
                    ImmutableMethodParameter("I", null, "age"),
                ),
                "V",
                AccessFlags.PUBLIC.value,
                null,
                null,
                methodImpl,
            )
        val classDef =
            ImmutableClassDef(
                "Lcom/test/Hello;",
                AccessFlags.PUBLIC.value,
                "Ljava/lang/Object;",
                null,
                null,
                null,
                null,
                listOf(method),
            )
        return ImmutableDexFile(Opcodes.forDexVersion(37), listOf(classDef))
    }

    private fun buildDexWithConstString(s: String): ImmutableDexFile {
        val methodImpl =
            ImmutableMethodImplementation(
                2,
                listOf(
                    ImmutableInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference(s)),
                    ImmutableInstruction10x(Opcode.RETURN_VOID),
                ),
                null,
                null,
            )
        val method =
            ImmutableMethod(
                "Lcom/test/Hello;",
                "test",
                emptyList(),
                "V",
                AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                null,
                null,
                methodImpl,
            )
        val classDef =
            ImmutableClassDef(
                "Lcom/test/Hello;",
                AccessFlags.PUBLIC.value,
                "Ljava/lang/Object;",
                null,
                null,
                null,
                null,
                listOf(method),
            )
        return ImmutableDexFile(Opcodes.forDexVersion(37), listOf(classDef))
    }

    private fun buildDexWithConstStringAndParams(s: String): ImmutableDexFile {
        val methodImpl =
            ImmutableMethodImplementation(
                3,
                listOf(
                    ImmutableInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference(s)),
                    ImmutableInstruction10x(Opcode.RETURN_VOID),
                ),
                null,
                null,
            )
        val method =
            ImmutableMethod(
                "Lcom/test/Hello;",
                "process",
                listOf(ImmutableMethodParameter("Ljava/lang/String;", null, "input")),
                "V",
                AccessFlags.PUBLIC.value,
                null,
                null,
                methodImpl,
            )
        val classDef =
            ImmutableClassDef(
                "Lcom/test/Hello;",
                AccessFlags.PUBLIC.value,
                "Ljava/lang/Object;",
                null,
                null,
                null,
                null,
                listOf(method),
            )
        return ImmutableDexFile(Opcodes.forDexVersion(37), listOf(classDef))
    }

    private fun buildDexWithSdkClass(): ImmutableDexFile {
        val methodImpl =
            ImmutableMethodImplementation(
                2,
                listOf(
                    ImmutableInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference("sdk_internal")),
                    ImmutableInstruction10x(Opcode.RETURN_VOID),
                ),
                null,
                null,
            )
        val method =
            ImmutableMethod(
                "Lcom/xcj/defender/Internal;",
                "init",
                emptyList(),
                "V",
                AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                null,
                null,
                methodImpl,
            )
        val classDef =
            ImmutableClassDef(
                "Lcom/xcj/defender/Internal;",
                AccessFlags.PUBLIC.value,
                "Ljava/lang/Object;",
                null,
                null,
                null,
                null,
                listOf(method),
            )
        return ImmutableDexFile(Opcodes.forDexVersion(37), listOf(classDef))
    }

    private fun writeDexToBytes(dex: ImmutableDexFile): ByteArray {
        val tmp = File.createTempFile("t4_test", ".dex")
        try {
            DexFileFactory.writeDexFile(tmp.absolutePath, dex)
            return tmp.readBytes()
        } finally {
            tmp.delete()
        }
    }

    /**
     * 遍历 DEX 找到第一个非零 parameter_name,返回其在字节数组中的偏移。
     */
    private fun findFirstNonZeroParameterName(dex: ByteArray): Int? {
        val buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        for (i in 0 until classDefsSize) {
            val classDefOff = classDefsOff + i * 32
            val classDataOff = buf.getInt(classDefOff + 24)
            if (classDataOff == 0) continue

            var pos = classDataOff
            val (sfSize, p1) = cmd.readUleb128(dex, pos)
            pos = p1
            val (ifSize, p2) = cmd.readUleb128(dex, pos)
            pos = p2
            val (dmSize, p3) = cmd.readUleb128(dex, pos)
            pos = p3
            val (vmSize, p4) = cmd.readUleb128(dex, pos)
            pos = p4

            pos = cmd.skipEncodedFields(dex, pos, sfSize + ifSize)

            for (m in 0 until (dmSize + vmSize)) {
                val (_, pa) = cmd.readUleb128(dex, pos)
                pos = pa
                val (_, pb) = cmd.readUleb128(dex, pos)
                pos = pb
                val (codeOff, pc) = cmd.readUleb128(dex, pos)
                pos = pc
                if (codeOff == 0) continue

                val debugInfoOff = buf.getInt(codeOff + 8)
                if (debugInfoOff == 0) continue

                var dpos = debugInfoOff
                val (_, d1) = cmd.readUleb128(dex, dpos)
                dpos = d1
                val (paramsSize, d2) = cmd.readUleb128(dex, dpos)
                dpos = d2

                for (pi in 0 until paramsSize) {
                    val (nameVal, nameEnd) = cmd.readUleb128(dex, dpos)
                    if (nameVal != 0) return dpos
                    dpos = nameEnd
                }
            }
        }
        return null
    }

    /**
     * 在指定偏移写入指定编码长度的 ULEB128 值(保持长度不变)。
     */
    private fun writeUleb128EqualLength(
        data: ByteArray,
        offset: Int,
        encLen: Int,
        value: Int,
    ) {
        var v = value
        for (i in 0 until encLen) {
            val isLast = (i == encLen - 1)
            var b = v and 0x7F
            v = v ushr 7
            if (!isLast) b = b or 0x80
            data[offset + i] = b.toByte()
        }
    }

    /**
     * 验证 DEX 中所有 parameter_name 索引在合法范围内。
     */
    private fun assertAllParameterNamesInRange(
        dex: ByteArray,
        stringIdsSize: Int,
    ) {
        val buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        for (i in 0 until classDefsSize) {
            val classDefOff = classDefsOff + i * 32
            val classDataOff = buf.getInt(classDefOff + 24)
            if (classDataOff == 0) continue

            var pos = classDataOff
            val (sfSize, p1) = cmd.readUleb128(dex, pos)
            pos = p1
            val (ifSize, p2) = cmd.readUleb128(dex, pos)
            pos = p2
            val (dmSize, p3) = cmd.readUleb128(dex, pos)
            pos = p3
            val (vmSize, p4) = cmd.readUleb128(dex, pos)
            pos = p4

            pos = cmd.skipEncodedFields(dex, pos, sfSize + ifSize)

            for (m in 0 until (dmSize + vmSize)) {
                val (_, pa) = cmd.readUleb128(dex, pos)
                pos = pa
                val (_, pb) = cmd.readUleb128(dex, pos)
                pos = pb
                val (codeOff, pc) = cmd.readUleb128(dex, pos)
                pos = pc
                if (codeOff == 0) continue

                val debugInfoOff = buf.getInt(codeOff + 8)
                if (debugInfoOff == 0) continue

                var dpos = debugInfoOff
                val (_, d1) = cmd.readUleb128(dex, dpos)
                dpos = d1
                val (paramsSize, d2) = cmd.readUleb128(dex, dpos)
                dpos = d2

                for (pi in 0 until paramsSize) {
                    val (nameVal, nameEnd) = cmd.readUleb128(dex, dpos)
                    if (nameVal != 0) {
                        val strIdx = nameVal - 1
                        assertTrue(
                            "parameter_name 索引 $strIdx 应 < string_ids_size $stringIdsSize",
                            strIdx < stringIdsSize,
                        )
                    }
                    dpos = nameEnd
                }
            }
        }
    }
}
