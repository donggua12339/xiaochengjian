package com.xcj.injector.dexstring

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.BuilderInstruction
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21s
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31i
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction3rc
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21c
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableField
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21s
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction22c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction23x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableFieldReference
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference
import org.slf4j.LoggerFactory
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
class DexStringEncryptor(
    private val xorKey: ByteArray,
    includePrefixes: List<String> = emptyList(),
) {
    private val logger = LoggerFactory.getLogger(DexStringEncryptor::class.java)

    /** 业务包前缀(dalvik 描述符形式);非空时仅加密这些包下的类。
     * kotlin/androidx 等库类加载早于 defender 且类初始化对字符串解密敏感,
     * 加密它们会直接 VerifyError(2026-08-06 真机实证),必须按业务包白名单收敛。 */
    private val includeDescriptors: List<String> =
        includePrefixes.map { "L${it.replace('.', '/')}" }

    /** 加密后的字符串表: index → XOR(UTF-8 bytes) */
    private val encryptedTable = LinkedHashMap<Int, ByteArray>()
    private val stringIndexMap = LinkedHashMap<String, Int>()
    private var nextIndex = 0

    companion object {
        private const val DECRYPTOR_CLASS = "Lcom/xcj/defender/DexStringDecryptor;"
        private const val DECRYPTOR_METHOD = "get"
        private const val DECRYPTOR_DESC = "(I)Ljava/lang/String;"

        /** Application 类描述符:其 <clinit> 早于 DefenderInitProvider,不可注入解密调用 */
        private const val APPLICATION_CLASS = "Landroid/app/Application;"

        /** 生成随机 XOR key(16 字节) */
        fun generateKey(): ByteArray {
            val key = ByteArray(16)
            SecureRandom().nextBytes(key)
            return key
        }
    }

    /**
     * 单个 DEX 的处理结果。
     * @param classes 改写后的类列表(不含 XcjEncStringTable)
     * @param modified 本 dex 是否有字符串被加密
     */
    data class ProcessResult(
        val classes: List<com.android.tools.smali.dexlib2.iface.ClassDef>,
        val modified: Boolean,
    )

    /**
     * 处理单个 DEX 文件。
     *
     * 注意:不注入 XcjEncStringTable——表含全部 dex 累计的字符串,
     * 由调用方在处理完所有 dex 后注入最后一个被修改的 dex(避免漏条目/重复类)。
     */
    fun processDex(dexFile: DexBackedDexFile): ProcessResult {
        val resultClasses = mutableListOf<com.android.tools.smali.dexlib2.iface.ClassDef>()
        var dexModified = false
        // superclass 链查询表(判定 Application 子类用,每 dex 构建一次)
        val superMap: Map<String, String?> = dexFile.classes.associate { it.type to it.superclass }

        for (classDef in dexFile.classes) {
            // 跳过 SDK 自身的类(不加密 SDK 内部字符串)
            if (classDef.type.startsWith("Lcom/xcj/defender/")) {
                resultClasses.add(classDef) // 保留原始 DexBackedClassDef
                continue
            }

            // 业务包白名单:只加密 includeDescriptors 命中的类。
            // 库类(kotlin/androidx/java/…)不加密——它们先于 defender 加载,
            // 且类初始化路径字符串被换为解密调用会 VerifyError。
            if (includeDescriptors.isNotEmpty() &&
                includeDescriptors.none { classDef.type.startsWith(it) }
            ) {
                resultClasses.add(classDef) // 保留原始 DexBackedClassDef
                continue
            }

            // Application 子类的 <clinit> 在 ContentProvider(DefenderInitProvider)之前执行,
            // 此时 defender SO 未加载,DexStringDecryptor.get 会 UnsatisfiedLinkError。
            // 该类的字符串保持明文(安全性由其他加固层兜底)。
            val isApplicationClass = isSubclassOf(classDef.superclass, APPLICATION_CLASS, superMap)

            // === 静态 String 字段初始值加密(const val / static final String)===
            // 这类字符串以 encoded_value 存放,不是 const-string 指令,单独处理:
            // 移除初始值,在 <clinit> 开头注入 DexStringDecryptor.get(index) 赋值。
            val fieldAssignments =
                mutableListOf<Pair<com.android.tools.smali.dexlib2.iface.reference.FieldReference, Int>>()
            val newFields = mutableListOf<com.android.tools.smali.dexlib2.iface.Field>()
            var fieldsModified = false
            for (field in classDef.fields) {
                val init = field.initialValue
                if (!isApplicationClass &&
                    AccessFlags.STATIC.isSet(field.accessFlags) &&
                    field.type == "Ljava/lang/String;" &&
                    init is com.android.tools.smali.dexlib2.iface.value.StringEncodedValue &&
                    init.value.length > 2
                ) {
                    val index = getOrAssignIndex(init.value)
                    fieldAssignments.add(
                        ImmutableFieldReference(classDef.type, field.name, field.type) to index,
                    )
                    newFields.add(
                        ImmutableField(
                            classDef.type,
                            field.name,
                            field.type,
                            field.accessFlags,
                            null, // 初始值移除,改由 <clinit> 解密赋值
                            field.annotations,
                            field.hiddenApiRestrictions,
                        ),
                    )
                    fieldsModified = true
                } else {
                    newFields.add(field)
                }
            }

            // 第一遍: 检查此 class 是否有需要替换的 const-string
            var classModified = false
            val modifiedMethods = mutableListOf<com.android.tools.smali.dexlib2.iface.Method>()

            for (method in classDef.methods) {
                val impl = method.implementation
                if (impl == null) {
                    modifiedMethods.add(method) // 抽象方法,保留原始
                    continue
                }

                /* 必须用 MutableMethodImplementation:其分支目标以 Label 表示,
                 * 插入/替换指令后自动重定位分支与 try 块。
                 * ImmutableInstruction 存绝对偏移,const-string(2 单元)换成
                 * 5 单元序列后,跨越替换点的分支目标全部失效
                 * (2026-08-06 真机 VerifyError: invalid branch target)。 */
                val original = impl.instructions.toList()
                val replaceIdx =
                    original.indices.filter { i ->
                        val ins = original[i]
                        ins.opcode == Opcode.CONST_STRING &&
                            ((ins as Instruction21c).reference as StringReference).string.length > 2
                    }
                if (replaceIdx.isEmpty()) {
                    modifiedMethods.add(method) // 未修改的方法: 保留原始引用
                    continue
                }

                classModified = true
                val mutable = MutableMethodImplementation(impl)
                // 倒序替换:插入不影响更小索引
                for (i in replaceIdx.asReversed()) {
                    val instr21c = original[i] as Instruction21c
                    val plaintext = (instr21c.reference as StringReference).string
                    val index = getOrAssignIndex(plaintext)
                    val register = instr21c.registerA
                    mutable.replaceInstruction(i, buildConst(register, index))
                    mutable.addInstruction(i + 1, buildInvoke(register))
                    mutable.addInstruction(
                        i + 2,
                        BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, register),
                    )
                }
                modifiedMethods.add(
                    com.android.tools.smali.dexlib2.immutable.ImmutableMethod(
                        classDef.type,
                        method.name,
                        /* 参数类型取自 proto type_list(parameterTypes),不触发 debug 流读取;
                         * 参数名/参数注解属 debug/注释信息,输出 dex 会整体剥离 */
                        method.parameterTypes.map { t ->
                            com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter(
                                t.toString(),
                                null,
                                null,
                            )
                        },
                        method.returnType,
                        method.accessFlags,
                        method.annotations,
                        method.hiddenApiRestrictions,
                        mutable,
                    ),
                )
            }

            // === <clinit> 注入:为移除初始值的静态 String 字段解密赋值 ===
            if (fieldAssignments.isNotEmpty()) {
                injectClinitAssignments(classDef.type, modifiedMethods, fieldAssignments)
                classModified = true
            }

            if (classModified || fieldsModified) {
                dexModified = true
                resultClasses.add(
                    ImmutableClassDef(
                        classDef.type,
                        classDef.accessFlags,
                        classDef.superclass,
                        classDef.interfaces,
                        classDef.sourceFile,
                        classDef.annotations,
                        newFields,
                        modifiedMethods,
                    ),
                )
            } else {
                resultClasses.add(classDef) // 未修改的 class: 保留原始 DexBackedClassDef
            }
        }

        return ProcessResult(resultClasses, dexModified)
    }

    /** 构造 const 指令:索引在 short 范围内用 CONST_16,否则 CONST(31i) */
    private fun buildConst(
        register: Int,
        index: Int,
    ): BuilderInstruction =
        if (index <= Short.MAX_VALUE) {
            BuilderInstruction21s(Opcode.CONST_16, register, index)
        } else {
            BuilderInstruction31i(Opcode.CONST, register, index)
        }

    /** 构造 DexStringDecryptor.get(I) 调用:寄存器 ≤15 用 35c,否则 3rc */
    private fun buildInvoke(register: Int): BuilderInstruction {
        val methodRef =
            ImmutableMethodReference(
                DECRYPTOR_CLASS,
                DECRYPTOR_METHOD,
                listOf("I"),
                "Ljava/lang/String;",
            )
        return if (register <= 15) {
            BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, register, 0, 0, 0, 0, methodRef)
        } else {
            BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, register, 1, methodRef)
        }
    }

    /**
     * 在 <clinit> 头部前置静态 String 字段的解密赋值指令序列。
     *
     * 每字段: const v0,idx → invoke-static DexStringDecryptor.get(I) →
     * move-result-object → sput-object。
     *
     * 用 MutableMethodImplementation 前置:Label 自动重定位原方法体的分支/try 块。
     * 临时寄存器用 v0——<clinit> 入口所有寄存器未初始化,原代码必先写后读,
     * 前置覆写 v0 不引入新的验证问题(2026-08-06 由绝对偏移方案改为 Label 方案)。
     * 无 <clinit> 或原实现 0 寄存器时新建(1 寄存器 + RETURN_VOID)。
     */
    private fun injectClinitAssignments(
        classType: String,
        methods: MutableList<com.android.tools.smali.dexlib2.iface.Method>,
        assignments: List<Pair<com.android.tools.smali.dexlib2.iface.reference.FieldReference, Int>>,
    ) {
        fun buildAssigns(reg: Int): List<BuilderInstruction> {
            val instrs = mutableListOf<BuilderInstruction>()
            for ((fieldRef, index) in assignments) {
                instrs.add(buildConst(reg, index))
                instrs.add(buildInvoke(reg))
                instrs.add(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, reg))
                instrs.add(BuilderInstruction21c(Opcode.SPUT_OBJECT, reg, fieldRef))
            }
            return instrs
        }

        val clinitIdx = methods.indexOfFirst { it.name == "<clinit>" && it.returnType == "V" }
        if (clinitIdx >= 0) {
            val old = methods[clinitIdx]
            val oldImpl = old.implementation
            val newImpl =
                if (oldImpl != null && oldImpl.registerCount >= 1) {
                    val mutable = MutableMethodImplementation(oldImpl)
                    buildAssigns(0).forEachIndexed { k, ins -> mutable.addInstruction(k, ins) }
                    mutable
                } else {
                    // 无实现或 0 寄存器(仅 return-void 之类):重建
                    val mutable = MutableMethodImplementation(1)
                    buildAssigns(0).forEach { mutable.addInstruction(it) }
                    mutable.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))
                    mutable
                }
            methods[clinitIdx] =
                ImmutableMethod(
                    classType,
                    old.name,
                    old.parameterTypes.map { t -> ImmutableMethodParameter(t.toString(), null, null) },
                    old.returnType,
                    old.accessFlags,
                    old.annotations,
                    old.hiddenApiRestrictions,
                    newImpl,
                )
        } else {
            val mutable = MutableMethodImplementation(1)
            buildAssigns(0).forEach { mutable.addInstruction(it) }
            mutable.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))
            methods.add(
                ImmutableMethod(
                    classType,
                    "<clinit>",
                    emptyList(),
                    "V",
                    AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value,
                    null,
                    null,
                    mutable,
                ),
            )
        }
    }

    /** 沿 dex 内 superclass 链判定是否为 targetType 的(间接)子类 */
    private fun isSubclassOf(
        start: String?,
        targetType: String,
        superMap: Map<String, String?>,
    ): Boolean {
        var cur = start
        var depth = 0
        while (cur != null && depth < 64) {
            if (cur == targetType) return true
            cur = superMap[cur]
            depth++
        }
        return false
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
     *
     * 由调用方在处理完所有 dex 后,把返回的类追加进最后一个被修改的 dex。
     */
    fun buildEncStringTableClassDef(): ImmutableClassDef {
        val typeDescriptor = "Lcom/xcj/defender/XcjEncStringTable;"
        val instructions = mutableListOf<ImmutableInstruction>()

        // v3 = "ISO-8859-1" (charset name, 复用)
        instructions.add(
            ImmutableInstruction21c(
                Opcode.CONST_STRING,
                3,
                ImmutableStringReference("ISO-8859-1"),
            ),
        )
        // v0 = new Object[table_size][]
        instructions.add(ImmutableInstruction21s(Opcode.CONST_16, 0, encryptedTable.size))
        instructions.add(
            ImmutableInstruction22c(
                Opcode.NEW_ARRAY,
                0,
                0,
                ImmutableTypeReference("[[B"),
            ),
        )

        for ((index, bytes) in encryptedTable) {
            // v2 = const-string "<ISO-8859-1 encoded encrypted bytes>"
            val isoStr = String(bytes, Charsets.ISO_8859_1)
            instructions.add(
                ImmutableInstruction21c(
                    Opcode.CONST_STRING,
                    2,
                    ImmutableStringReference(isoStr),
                ),
            )
            // v2 = v2.getBytes("ISO-8859-1")
            instructions.add(
                ImmutableInstruction35c(
                    Opcode.INVOKE_VIRTUAL,
                    2,
                    2,
                    3,
                    0,
                    0,
                    0,
                    ImmutableMethodReference(
                        "Ljava/lang/String;",
                        "getBytes",
                        listOf("Ljava/lang/String;"),
                        "[B",
                    ),
                ),
            )
            instructions.add(ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 2))
            // DATA[index] = v2
            instructions.add(ImmutableInstruction21s(Opcode.CONST_16, 1, index))
            instructions.add(ImmutableInstruction23x(Opcode.APUT_OBJECT, 2, 0, 1))
        }

        // XcjEncStringTable.DATA = v0
        instructions.add(
            ImmutableInstruction21c(
                Opcode.SPUT_OBJECT,
                0,
                ImmutableFieldReference(typeDescriptor, "DATA", "[[B"),
            ),
        )
        instructions.add(ImmutableInstruction10x(Opcode.RETURN_VOID))

        val methodImpl = ImmutableMethodImplementation(4, instructions, null, null)
        val clinit =
            ImmutableMethod(
                typeDescriptor,
                "<clinit>",
                emptyList(),
                "V",
                AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value,
                null,
                null,
                methodImpl,
            )
        val dataField =
            ImmutableField(
                typeDescriptor,
                "DATA",
                "[[B",
                AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                null as com.android.tools.smali.dexlib2.iface.value.EncodedValue?,
                emptySet<com.android.tools.smali.dexlib2.iface.Annotation>(),
                null,
            )

        return ImmutableClassDef(
            typeDescriptor,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            null,
            null,
            null,
            listOf(dataField),
            listOf(clinit),
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
