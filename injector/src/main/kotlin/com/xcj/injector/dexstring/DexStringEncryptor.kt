package com.xcj.injector.dexstring

import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcode
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.dexbacked.DexBackedDexFile
import org.jf.dexlib2.iface.instruction.formats.Instruction21c
import org.jf.dexlib2.immutable.ImmutableClassDef
import org.jf.dexlib2.immutable.ImmutableDexFile
import org.jf.dexlib2.AccessFlags
import org.jf.dexlib2.immutable.ImmutableField
import org.jf.dexlib2.immutable.ImmutableMethod
import org.jf.dexlib2.immutable.ImmutableMethodImplementation
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction10x
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction11x
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction21c
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction21s
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction22c
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction23x
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction35c
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction3rc
import org.jf.dexlib2.iface.reference.StringReference
import org.jf.dexlib2.immutable.reference.ImmutableFieldReference
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference
import org.jf.dexlib2.immutable.reference.ImmutableStringReference
import org.jf.dexlib2.immutable.reference.ImmutableTypeReference
import org.slf4j.LoggerFactory
import java.io.File
import java.security.SecureRandom

/**
 * T4 DEX 字符串加密器(ADR 0090 授权)。
 *
 * 构建期工具:读取 APK 中的 DEX 文件,将所有 const-string 指令替换为
 * 对 native 解密函数的调用。加密后的字符串存入生成的 XcjEncStringTable 类。
 *
 * 替换逻辑:
 *   原始: const-string vX, "plaintext"
 *   替换: const/16 vX, INDEX
 *         invoke-static {vX}, Lcom/xcj/defender/DexStringDecryptor;->get(I)Ljava/lang/String;
 *         move-result-object vX
 *
 * 安全性:加密数据在 DEX(可见但密文),密钥在 native .so(受 X0 保护)。
 */
class DexStringEncryptor(private val xorKey: ByteArray) {

    private val logger = LoggerFactory.getLogger(DexStringEncryptor::class.java)

    /** 加密后的字符串表: index → XOR(UTF-8 bytes) */
    private val encryptedTable = LinkedHashMap<Int, ByteArray>()
    private val stringIndexMap = LinkedHashMap<String, Int>()
    private var nextIndex = 0

    companion object {
        private const val DECRYPTOR_CLASS = "Lcom/xcj/defender/DexStringDecryptor;"
        private const val DECRYPTOR_METHOD = "get"
        private const val DECRYPTOR_DESC = "(I)Ljava/lang/String;"

        /** 生成随机 XOR key(16 字节) */
        fun generateKey(): ByteArray {
            val key = ByteArray(16)
            SecureRandom().nextBytes(key)
            return key
        }
    }

    /**
     * 处理单个 DEX 文件,返回修改后的 ClassDef 列表。
     */
    fun processDex(dexFile: DexBackedDexFile): List<ImmutableClassDef> {
        val modifiedClasses = mutableListOf<ImmutableClassDef>()

        for (classDef in dexFile.classes) {
            // 跳过 SDK 自身的类(不加密 SDK 内部字符串)
            if (classDef.type.startsWith("Lcom/xcj/defender/")) {
                modifiedClasses.add(ImmutableClassDef.of(classDef))
                continue
            }

            val modifiedMethods = classDef.methods.map { method ->
                val impl = method.implementation
                // Strip parameter names(dexlib2 重排 string table 后 parameter_name 索引失效)
                val strippedParams = method.parameters.map { p ->
                    org.jf.dexlib2.immutable.ImmutableMethodParameter(
                        p.type, p.annotations, null
                    )
                }
                if (impl == null) {
                    return@map org.jf.dexlib2.immutable.ImmutableMethod(
                        classDef.type, method.name, strippedParams, method.returnType,
                        method.accessFlags, method.annotations, method.hiddenApiRestrictions, null
                    )
                }
                val instructions = impl.instructions
                val newInstructions = mutableListOf<ImmutableInstruction>()
                var modified = false

                for (instruction in instructions) {
                    if (instruction.opcode == Opcode.CONST_STRING) {
                        val instr21c = instruction as Instruction21c
                        val ref = instr21c.reference as StringReference
                        val plaintext = ref.string

                        // 跳过空字符串和极短字符串(不值得加密)
                        if (plaintext.length <= 2) {
                            newInstructions.add(ImmutableInstruction.of(instruction))
                            continue
                        }

                        val index = getOrAssignIndex(plaintext)
                        val register = instr21c.registerA

                        // const/16 vX, INDEX
                        newInstructions.add(
                            ImmutableInstruction21s(Opcode.CONST_16, register, index)
                        )
                        // invoke-static {vX} or {vX..vX}, DexStringDecryptor.get(I)
                        val methodRef = ImmutableMethodReference(
                            DECRYPTOR_CLASS,
                            DECRYPTOR_METHOD,
                            listOf("I"),
                            "Ljava/lang/String;"
                        )
                        if (register <= 15) {
                            newInstructions.add(
                                ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, register, 0, 0, 0, 0, methodRef)
                            )
                        } else {
                            newInstructions.add(
                                ImmutableInstruction3rc(Opcode.INVOKE_STATIC_RANGE, register, 1, methodRef)
                            )
                        }
                        // move-result-object vX
                        newInstructions.add(
                            ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, register)
                        )
                        modified = true
                    } else {
                        newInstructions.add(ImmutableInstruction.of(instruction))
                    }
                }

                if (modified) {
                    // 重建 method
                    val newImpl = org.jf.dexlib2.immutable.ImmutableMethodImplementation(
                        impl.registerCount,
                        newInstructions,
                        impl.tryBlocks,
                        null  // strip debug info(修改指令后 debug 索引失效)
                    )
                    org.jf.dexlib2.immutable.ImmutableMethod(
                        classDef.type,
                        method.name,
                        strippedParams,
                        method.returnType,
                        method.accessFlags,
                        method.annotations,
                        method.hiddenApiRestrictions,
                        newImpl
                    )
                } else {
                    // 未修改指令,但仍需 strip debug info + parameter names
                    val origImpl = method.implementation
                    if (origImpl != null) {
                        val strippedImpl = org.jf.dexlib2.immutable.ImmutableMethodImplementation(
                            origImpl.registerCount, origImpl.instructions, origImpl.tryBlocks, null
                        )
                        org.jf.dexlib2.immutable.ImmutableMethod(
                            classDef.type, method.name, strippedParams, method.returnType,
                            method.accessFlags, method.annotations, method.hiddenApiRestrictions, strippedImpl
                        )
                    } else {
                        org.jf.dexlib2.immutable.ImmutableMethod(
                            classDef.type, method.name, strippedParams, method.returnType,
                            method.accessFlags, method.annotations, method.hiddenApiRestrictions, null
                        )
                    }
                }
            }

            modifiedClasses.add(
                ImmutableClassDef(
                    classDef.type,
                    classDef.accessFlags,
                    classDef.superclass,
                    classDef.interfaces,
                    classDef.sourceFile,
                    classDef.annotations,
                    classDef.fields.map { org.jf.dexlib2.immutable.ImmutableField.of(it) },
                    modifiedMethods
                )
            )
        }

        // 注入 XcjEncStringTable 类(持有加密数据表)
        if (encryptedTable.isNotEmpty()) {
            modifiedClasses.add(buildEncStringTableClassDef())
        }

        return modifiedClasses
    }

    /**
     * 获取或分配字符串索引,同时加密存入表。
     * smali 管线调用此方法为每个 const-string 分配 index。
     */
    fun getOrAssignIndex(plaintext: String): Int {
        stringIndexMap[plaintext]?.let { return it }
        val index = nextIndex++
        stringIndexMap[plaintext] = index
        encryptedTable[index] = xorEncrypt(plaintext.toByteArray(Charsets.UTF_8))
        return index
    }

    private fun xorEncrypt(data: ByteArray): ByteArray {
        val result = ByteArray(data.size)
        for (i in data.indices) {
            result[i] = (data[i].toInt() xor xorKey[i % xorKey.size].toInt()).toByte()
        }
        return result
    }

    /** 获取加密后的字符串表(供生成 XcjEncStringTable 类) */
    fun getEncryptedTable(): Map<Int, ByteArray> = encryptedTable.toMap()

    /** 获取统计信息 */
    fun getStats(): String = "加密 ${encryptedTable.size} 个唯一字符串"

    /**
     * 用 dexlib2 API 构建 XcjEncStringTable 类(加密数据表)。
     * 使用 const-string + String.getBytes("ISO-8859-1") 方式存储加密字节,
     * 避免 fill-array-data 的 ArrayPayload 构建复杂度。
     */
    private fun buildEncStringTableClassDef(): ImmutableClassDef {
        val TYPE = "Lcom/xcj/defender/XcjEncStringTable;"
        val instructions = mutableListOf<ImmutableInstruction>()

        // v3 = "ISO-8859-1" (charset name, 复用)
        instructions.add(ImmutableInstruction21c(
            Opcode.CONST_STRING, 3, ImmutableStringReference("ISO-8859-1")
        ))
        // v0 = new Object[table_size][]
        instructions.add(ImmutableInstruction21s(Opcode.CONST_16, 0, encryptedTable.size))
        instructions.add(ImmutableInstruction22c(
            Opcode.NEW_ARRAY, 0, 0, ImmutableTypeReference("[[B")
        ))

        for ((index, bytes) in encryptedTable) {
            // v2 = const-string "<ISO-8859-1 encoded encrypted bytes>"
            val isoStr = String(bytes, Charsets.ISO_8859_1)
            instructions.add(ImmutableInstruction21c(
                Opcode.CONST_STRING, 2, ImmutableStringReference(isoStr)
            ))
            // v2 = v2.getBytes("ISO-8859-1")
            instructions.add(ImmutableInstruction35c(
                Opcode.INVOKE_VIRTUAL, 2, 2, 3, 0, 0, 0,
                ImmutableMethodReference("Ljava/lang/String;", "getBytes",
                    listOf("Ljava/lang/String;"), "[B")
            ))
            instructions.add(ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 2))
            // DATA[index] = v2
            instructions.add(ImmutableInstruction21s(Opcode.CONST_16, 1, index))
            instructions.add(ImmutableInstruction23x(Opcode.APUT_OBJECT, 2, 0, 1))
        }

        // XcjEncStringTable.DATA = v0
        instructions.add(ImmutableInstruction21c(
            Opcode.SPUT_OBJECT, 0,
            ImmutableFieldReference(TYPE, "DATA", "[[B")
        ))
        instructions.add(ImmutableInstruction10x(Opcode.RETURN_VOID))

        val methodImpl = ImmutableMethodImplementation(4, instructions, null, null)
        val clinit = ImmutableMethod(
            TYPE, "<clinit>", emptyList(), "V",
            AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value,
            null, null, methodImpl
        )
        val dataField = ImmutableField(
            TYPE, "DATA", "[[B",
            AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
            null as org.jf.dexlib2.iface.value.EncodedValue?,
            emptySet<org.jf.dexlib2.iface.Annotation>(),
            null
        )

        return ImmutableClassDef(
            TYPE, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
            null, null, null, listOf(dataField), listOf(clinit)
        )
    }

    /**
     * 生成 XcjEncStringTable.smali 内容(注入到 DEX 中)。
     * 该类持有 static byte[][] DATA,供 DexStringDecryptor.get() 读取。
     */
    fun generateTableSmali(): String {
        val sb = StringBuilder()
        sb.appendLine(".class public Lcom/xcj/defender/XcjEncStringTable;")
        sb.appendLine(".super Ljava/lang/Object;")
        sb.appendLine()
        sb.appendLine(".field public static DATA:[[B")
        sb.appendLine()
        sb.appendLine(".method static constructor <clinit>()V")
        sb.appendLine("    .registers 3")
        sb.appendLine()
        sb.appendLine("    const/16 v0, ${encryptedTable.size}")
        sb.appendLine("    new-array v0, v0, [[B")
        sb.appendLine()

        for ((index, bytes) in encryptedTable) {
            sb.appendLine("    const/16 v1, $index")
            sb.appendLine("    const/16 v2, ${bytes.size}")
            sb.appendLine("    new-array v2, v2, [B")
            sb.appendLine("    fill-array-data v2, :str_$index")
            sb.appendLine("    aput-object v2, v0, v1")
            sb.appendLine()
        }

        sb.appendLine("    sput-object v0, Lcom/xcj/defender/XcjEncStringTable;->DATA:[[B")
        sb.appendLine("    return-void")

        // array data blocks(after return-void,valid in smali)
        for ((index, bytes) in encryptedTable) {
            sb.appendLine()
            sb.appendLine("    :str_$index")
            sb.appendLine("    .array-data 1")
            for (b in bytes) {
                sb.appendLine("        ${String.format("0x%02x", b.toInt() and 0xFF)}")
            }
            sb.appendLine("    .end array-data")
        }

        sb.appendLine(".end method")
        return sb.toString()
    }

    /**
     * 生成 native 侧密钥头文件(供 defender-sdk 编译)。
     */
    fun generateKeyHeader(): String {
        val sb = StringBuilder()
        sb.appendLine("/* 自动生成 - T4 DEX 字符串解密密钥(ADR 0090) */")
        sb.appendLine("#ifndef T4_STR_KEY_H")
        sb.appendLine("#define T4_STR_KEY_H")
        sb.appendLine()
        sb.append("#define T4_XOR_KEY_LEN ${xorKey.size}")
        sb.appendLine()
        sb.append("static const unsigned char T4_XOR_KEY[] = {")
        sb.append(xorKey.joinToString(", ") { String.format("0x%02x", it.toInt() and 0xFF) })
        sb.appendLine("};")
        sb.appendLine()
        sb.appendLine("#endif /* T4_STR_KEY_H */")
        return sb.toString()
    }
}
