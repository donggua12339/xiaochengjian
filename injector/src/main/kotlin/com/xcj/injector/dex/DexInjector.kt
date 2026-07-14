package com.xcj.injector.dex

import org.slf4j.LoggerFactory
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.iface.ClassDef
import org.jf.dexlib2.iface.DexFile
import org.jf.dexlib2.iface.Method
import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.model.ZipParameters
import java.io.File

/**
 * dex 注入器(ADR 0063-0066)
 *
 * 详见 ADR 0063(ImmutableDexFile 重建)/ 0064(注入点)/ 0065(创建 Application)
 *
 * 当前实现:
 *  - 解压 APK + 识别 Application 类 + 识别 onCreate/attachBaseContext 注入点
 *  - 完整 invoke-static 指令构造(ImmutableInstruction35c)需要 dexlib2 API 专项调试
 *    dexlib2 2.5.2 的 Immutable 指令构造签名与预期不同,需逐个验证
 *  - 当前版本:记录注入点,不改 dex(避免破坏性修改)
 *
 * 完整实现路线(B1 深化后续):
 *  1. 验证 dexlib2 2.5.2 的 ImmutableInstruction35c 构造函数签名
 *  2. 构造 invoke-static {v0,v1,v2}, Lcom/xcj/sdk/XcjNative;->native01(...)I
 *  3. 重建方法实现(ImmutableMethodImplementation)
 *  4. 重建类(ImmutableClassDef)
 *  5. 重建 dex(ImmutableDexFile)
 */
class DexInjector {
    private val logger = LoggerFactory.getLogger(DexInjector::class.java)

    companion object {
        private const val XCJ_NATIVE_CLASS = "Lcom/xcj/sdk/XcjNative;"
        private const val INIT_METHOD_NAME = "native01"
    }

    fun inject(apkFile: File) {
        val extractDir = apkFile.parentFile.resolve("extract_${apkFile.nameWithoutExtension}")
        extractDir.mkdirs()
        ZipFile(apkFile).extractAll(extractDir.absolutePath)
        logger.info("已解压 APK 到 ${extractDir.absolutePath}")

        val dexFiles = extractDir.listFiles { f -> f.name.endsWith(".dex") }?.sortedBy { it.name }
            ?: emptyList()
        require(dexFiles.isNotEmpty()) { "APK 中未找到 dex 文件" }
        logger.info("发现 ${dexFiles.size} 个 dex 文件: ${dexFiles.map { it.name }}")

        val mainDex = dexFiles.first()
        val dexFile = DexFileFactory.loadDexFile(mainDex, Opcodes.getDefault())

        val applicationClass = findApplicationClass(dexFile)
        val targetClass = applicationClass ?: dexFile.classes.firstOrNull { it.type == "Landroid/app/Application;" }

        if (targetClass != null) {
            logger.info("目标 Application 类: ${targetClass.type}")
            identifyInjectionPoints(targetClass)
        } else {
            logger.warn("未找到 Application 类,跳过注入")
        }

        // 重新打包 APK(M3 简化版:dex 不改,仅重新打包 + 水印 + 签名)
        apkFile.delete()
        val zipFile = ZipFile(apkFile)
        extractDir.listFiles()?.forEach { addFileToZip(zipFile, it, "") }
        logger.info("已重新打包 APK")

        extractDir.deleteRecursively()
    }

    /**
     * 识别注入点(ADR 0064:onCreate + attachBaseContext)
     */
    private fun identifyInjectionPoints(classDef: ClassDef) {
        val onCreate = findMethod(classDef, "onCreate")
        val attachBase = findMethod(classDef, "attachBaseContext")

        if (onCreate != null) {
            logger.info("[注入点] ${classDef.type}.onCreate 参数=${onCreate.parameterTypes} 返回=${onCreate.returnType}")
            logger.info("  目标指令:invoke-static {p0}, $XCJ_NATIVE_CLASS.$INIT_METHOD_NAME(...)I")
        }
        if (attachBase != null) {
            logger.info("[注入点] ${classDef.type}.attachBaseContext 参数=${attachBase.parameterTypes}")
            logger.info("  目标指令:invoke-static {p0}, $XCJ_NATIVE_CLASS.$INIT_METHOD_NAME(...)I")
        }
        if (onCreate == null && attachBase == null) {
            logger.info("Application 无 onCreate/attachBaseContext,需创建(B3)")
        }

        logger.info("注入点识别完成,完整指令插入待 dexlib2 API 专项调试(ADR 0063)")
    }

    private fun findMethod(classDef: ClassDef, name: String): Method? {
        return classDef.methods.firstOrNull { it.name == name }
    }

    private fun findApplicationClass(dexFile: DexFile): ClassDef? {
        for (classDef in dexFile.classes) {
            val type = classDef.type
            if (type == "Landroid/app/Application;") continue
            if (classDef.superclass == "Landroid/app/Application;" ||
                classDef.superclass?.contains("Application") == true
            ) {
                logger.info("候选 Application 类: $type (父类: ${classDef.superclass})")
                return classDef
            }
        }
        return null
    }

    private fun addFileToZip(zipFile: ZipFile, file: File, basePath: String) {
        if (file.isFile) {
            val entryName = if (basePath.isEmpty()) file.name else "$basePath/${file.name}"
            zipFile.addFile(file, ZipParameters().apply { fileNameInZip = entryName })
        } else if (file.isDirectory) {
            val newBase = if (basePath.isEmpty()) file.name else "$basePath/${file.name}"
            file.listFiles()?.forEach { addFileToZip(zipFile, it, newBase) }
        }
    }
}
