package com.xcj.injector.dexstring

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableField
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.debug.ImmutableLineNumber
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import com.android.tools.smali.dexlib2.immutable.value.ImmutableStringEncodedValue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32

/**
 * T4 DEX 字符串加密 + debug 剥离 单元测试。
 *
 * 覆盖:
 *  - readUleb128 基础工具
 *  - stripDebugInfo 剥离 debug info(dexlib2 重排 string table 的根治方案)
 *  - DexStringEncryptor.processDex 加密 const-string + 静态 String 字段初始值
 */
class DexStringEncryptorTest {
    private val cmd = EncryptStringsCommand()

    // ===== readUleb128 =====

    @Test
    fun `readUleb128 零值`() {
        val (value, pos) = cmd.readUleb128(byteArrayOf(0x00), 0)
        assertEquals(0L, value)
        assertEquals(1, pos)
    }

    @Test
    fun `readUleb128 单字节`() {
        val (value, pos) = cmd.readUleb128(byteArrayOf(0x05), 0)
        assertEquals(5L, value)
        assertEquals(1, pos)
    }

    @Test
    fun `readUleb128 双字节 128`() {
        // 128 → ULEB128: 0x80 0x01
        val (value, pos) = cmd.readUleb128(byteArrayOf(0x80.toByte(), 0x01), 0)
        assertEquals(128L, value)
        assertEquals(2, pos)
    }

    @Test
    fun `readUleb128 三字节 16384`() {
        // 16384 → ULEB128: 0x80 0x80 0x01
        val data = byteArrayOf(0x80.toByte(), 0x80.toByte(), 0x01)
        val (value, pos) = cmd.readUleb128(data, 0)
        assertEquals(16384L, value)
        assertEquals(3, pos)
    }

    @Test
    fun `readUleb128 带偏移`() {
        val data = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0x0A)
        val (value, pos) = cmd.readUleb128(data, 2)
        assertEquals(10L, value)
        assertEquals(3, pos)
    }

    @Test
    fun `readUleb128 五字节超 Int 范围`() {
        // 0xFFFFFFFF = 4294967295 > Int.MAX_VALUE,必须用 Long 解码
        val data = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0x0F)
        val (value, pos) = cmd.readUleb128(data, 0)
        assertEquals(4294967295L, value)
        assertEquals(5, pos)
    }

    // ===== stripDebugInfo =====

    @Test
    fun `stripDebugInfo 清零 debug_info_off 且校验和有效`() {
        val bytes = writeDexToBytes(buildDexWithConstStringAndParams("test_strip_debug_info"))
        assertTrue("前置: dexlib2 应写出 debug info", collectDebugOffsets(bytes).isNotEmpty())

        val (stripped, count) = cmd.stripDebugInfo(bytes)
        assertTrue("应有 code_item 被清零 debug_info_off", count > 0)
        assertEquals("debug_info_off 应全部为 0", emptyList<Int>(), collectDebugOffsets(stripped))

        // SHA-1 signature 正确
        val sha1 = MessageDigest.getInstance("SHA-1")
        sha1.update(stripped, 32, stripped.size - 32)
        assertTrue("SHA-1 应正确", sha1.digest().contentEquals(stripped.copyOfRange(12, 32)))

        // adler32 checksum 正确
        val adler = Adler32()
        adler.update(stripped, 12, stripped.size - 12)
        assertEquals(
            "adler32 应正确",
            adler.value.toInt(),
            ByteBuffer.wrap(stripped).order(ByteOrder.LITTLE_ENDIAN).getInt(8),
        )

        // dexlib2 仍可解析
        val parsed = DexBackedDexFile(Opcodes.forDexVersion(37), stripped)
        assertTrue("剥离后 DEX 应可解析", parsed.classes.isNotEmpty())
    }

    @Test
    fun `stripDebugInfo debug 数据区被置零`() {
        val bytes = writeDexToBytes(buildDexWithConstStringAndParams("test_debug_region_zero"))
        val debugOffs = collectDebugOffsets(bytes)
        assertTrue(debugOffs.isNotEmpty())

        val (stripped, _) = cmd.stripDebugInfo(bytes)
        // 每个原 debug_info_off 起点处应为全零(空 debug item: line=0, params=0, END_SEQUENCE)
        for (off in debugOffs) {
            assertEquals("debug item 起始字节应被置零 @${off.toString(16)}", 0, stripped[off].toInt())
        }
    }

    @Test
    fun `stripDebugInfo 无 debug info 的 DEX 不破坏`() {
        val bytes = writeDexToBytes(buildDexWithConstString("no_debug_test_string"))
        val (stripped, _) = cmd.stripDebugInfo(bytes)
        val parsed = DexBackedDexFile(Opcodes.forDexVersion(37), stripped)
        assertTrue(parsed.classes.isNotEmpty())
    }

    // ===== DexStringEncryptor: const-string =====

    @Test
    fun `processDex 应加密 const-string 并标记 modified`() {
        val key = DexStringEncryptor.generateKey()
        val encryptor = DexStringEncryptor(key, listOf("com.test"))

        val dexBytes = writeDexToBytes(buildDexWithConstString("hello_world_test_string"))
        val dexFile = DexBackedDexFile(Opcodes.forDexVersion(37), dexBytes)
        val result = encryptor.processDex(dexFile)

        assertTrue("应标记 modified", result.modified)
        assertTrue("应加密至少 1 个字符串", encryptor.getEncryptedTable().isNotEmpty())
        // 表类由调用方在处理完所有 dex 后统一注入,processDex 自身不注入
        assertTrue(
            "processDex 不应注入表类",
            result.classes.none { it.type == "Lcom/xcj/defender/XcjEncStringTable;" },
        )
        assertEquals(
            "Lcom/xcj/defender/XcjEncStringTable;",
            encryptor.buildEncStringTableClassDef().type,
        )
    }

    @Test
    fun `processDex 跳过 SDK 命名空间`() {
        val key = DexStringEncryptor.generateKey()
        val encryptor = DexStringEncryptor(key, listOf("com.test"))

        val dexBytes = writeDexToBytes(buildDexWithSdkClass())
        val dexFile = DexBackedDexFile(Opcodes.forDexVersion(37), dexBytes)
        val result = encryptor.processDex(dexFile)

        // SDK 类不应被修改
        assertTrue("SDK 类不应被加密", !result.modified)
    }

    // ===== DexStringEncryptor: 静态 String 字段初始值 =====

    @Test
    fun `processDex 加密静态 String 字段初始值并注入 clinit`() {
        val encryptor = DexStringEncryptor(DexStringEncryptor.generateKey(), listOf("com.test"))
        val dexBytes = writeDexToBytes(buildDexWithStaticStringField("secret_business_value_123"))
        val dexFile = DexBackedDexFile(Opcodes.forDexVersion(37), dexBytes)
        val result = encryptor.processDex(dexFile)

        assertTrue("应标记 modified", result.modified)
        assertTrue("字段初始值字符串应入加密表", encryptor.getEncryptedTable().isNotEmpty())

        val cls = result.classes.first { it.type == "Lcom/test/Holder;" }
        // 字段初始值已移除
        val field = cls.staticFields.first { it.name == "SECRET" }
        assertNull("字段初始值应被移除", field.initialValue)

        // <clinit> 注入了解密赋值序列
        val clinit = cls.methods.first { it.name == "<clinit>" }
        val ops = clinit.implementation!!.instructions.map { it.opcode }
        assertTrue("应含 CONST_16", ops.contains(Opcode.CONST_16))
        assertTrue("应含 INVOKE_STATIC", ops.contains(Opcode.INVOKE_STATIC))
        assertTrue("应含 MOVE_RESULT_OBJECT", ops.contains(Opcode.MOVE_RESULT_OBJECT))
        assertTrue("应含 SPUT_OBJECT", ops.contains(Opcode.SPUT_OBJECT))
    }

    @Test
    fun `processDex 短字符串字段初始值不加密`() {
        val encryptor = DexStringEncryptor(DexStringEncryptor.generateKey(), listOf("com.test"))
        val dexBytes = writeDexToBytes(buildDexWithStaticStringField("ab"))
        val dexFile = DexBackedDexFile(Opcodes.forDexVersion(37), dexBytes)
        val result = encryptor.processDex(dexFile)

        assertTrue("≤2 字符不加密,不应 modified", !result.modified)
    }

    @Test
    fun `processDex Application 子类静态字段不加密`() {
        val encryptor = DexStringEncryptor(DexStringEncryptor.generateKey(), listOf("com.test"))
        val dexBytes = writeDexToBytes(buildDexWithApplicationClass("app_secret_value_xyz"))
        val dexFile = DexBackedDexFile(Opcodes.forDexVersion(37), dexBytes)
        val result = encryptor.processDex(dexFile)

        val cls = result.classes.first { it.type == "Lcom/test/MyApp;" }
        val field = cls.staticFields.first { it.name == "SECRET" }
        assertTrue(
            "Application 子类字段初始值应保留(其 clinit 早于 defender 加载)",
            field.initialValue != null,
        )
    }

    // ===== 其他 =====

    @Test
    fun `encryptStrings 端到端写出后经 stripDebugInfo 仍可解析`() {
        val key = DexStringEncryptor.generateKey()
        val encryptor = DexStringEncryptor(key, listOf("com.test"))

        // 用无 debug 的输入:dexlib2 自写 dex 的 debug 字符串索引可能越界,
        // 而 processDex 的 MutableMethodImplementation 会拷贝 debug items。
        // 生产输入是 d8 产物(debug 有效)不受影响;debug 剥离由专项测试覆盖。
        val dexBytes = writeDexToBytes(buildDexWithConstString("test_encrypt_string"))
        val dexFile = DexBackedDexFile(Opcodes.forDexVersion(37), dexBytes)
        val modified = encryptor.processDex(dexFile)

        val classes = modified.classes + encryptor.buildEncStringTableClassDef()
        val outputDex = ImmutableDexFile(Opcodes.forDexVersion(37), classes)
        val written = writeDexToBytes(outputDex)

        // 经 stripDebugInfo 后应可解析
        val (stripped, count) = cmd.stripDebugInfo(written)
        assertEquals(
            "strip 后 debug_info_off 应全为 0(诊断: count=$count, 残留=${collectDebugOffsets(stripped)})",
            emptyList<Int>(),
            collectDebugOffsets(stripped),
        )
        val parsed = DexBackedDexFile(Opcodes.forDexVersion(37), stripped)
        assertTrue("加密+strip 后 DEX 应可解析", parsed.classes.isNotEmpty())
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
        val encryptor = DexStringEncryptor(key, listOf("com.test"))
        val header = encryptor.generateKeyHeader()

        assertTrue(header.contains("#ifndef T4_STR_KEY_H"))
        assertTrue(header.contains("#define T4_XOR_KEY_LEN 16"))
        assertTrue(header.contains("0x01"))
        assertTrue(header.contains("0x10"))
    }

    // ===== helpers =====

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
                listOf(
                    ImmutableLineNumber(0, 42),
                    ImmutableLineNumber(0, 43),
                ),
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

    private fun buildDexWithStaticStringField(secret: String): ImmutableDexFile {
        val field =
            ImmutableField(
                "Lcom/test/Holder;",
                "SECRET",
                "Ljava/lang/String;",
                AccessFlags.STATIC.value or AccessFlags.FINAL.value,
                ImmutableStringEncodedValue(secret),
                emptySet(),
                null,
            )
        val classDef =
            ImmutableClassDef(
                "Lcom/test/Holder;",
                AccessFlags.PUBLIC.value,
                "Ljava/lang/Object;",
                null,
                null,
                null,
                listOf(field),
                emptyList(),
            )
        return ImmutableDexFile(Opcodes.forDexVersion(37), listOf(classDef))
    }

    private fun buildDexWithApplicationClass(secret: String): ImmutableDexFile {
        val field =
            ImmutableField(
                "Lcom/test/MyApp;",
                "SECRET",
                "Ljava/lang/String;",
                AccessFlags.STATIC.value or AccessFlags.FINAL.value,
                ImmutableStringEncodedValue(secret),
                emptySet(),
                null,
            )
        val classDef =
            ImmutableClassDef(
                "Lcom/test/MyApp;",
                AccessFlags.PUBLIC.value,
                "Landroid/app/Application;",
                null,
                null,
                null,
                listOf(field),
                emptyList(),
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

    /** 遍历 DEX 收集所有非零 debug_info_off */
    private fun collectDebugOffsets(dex: ByteArray): List<Int> {
        val buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)
        val result = mutableListOf<Int>()

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

            pos = cmd.skipEncodedFields(dex, pos, (sfSize + ifSize).toInt())

            for (m in 0 until (dmSize + vmSize).toInt()) {
                val (_, pa) = cmd.readUleb128(dex, pos)
                pos = pa
                val (_, pb) = cmd.readUleb128(dex, pos)
                pos = pb
                val (codeOff, pc) = cmd.readUleb128(dex, pos)
                pos = pc
                if (codeOff == 0L) continue

                val debugInfoOff = buf.getInt(codeOff.toInt() + 8)
                if (debugInfoOff != 0) result.add(debugInfoOff)
            }
        }
        return result
    }
}
