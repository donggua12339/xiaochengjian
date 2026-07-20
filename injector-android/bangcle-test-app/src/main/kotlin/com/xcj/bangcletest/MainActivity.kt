package com.xcj.bangcletest

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * 梆梆加固测试 APP
 *
 * 用途:给用户上梆梆官网加固后,用小城笺"自有 APK 诊断"功能的
 * 梆梆自检模式(ADR 0078)做端到端验证。
 *
 * 流程:
 *  1. ./gradlew :bangcle-test-app:assembleRelease 编出未加固的 APK
 *  2. 上传到梆梆官网(https://www.bangcle.com)做加固
 *  3. 加固后的 APK 用 injector-android 的"自有诊断"Tab 上传
 *  4. 后端 HardenerDetector 检测到梆梆 so -> 触发梆梆自检流程
 *  5. 验证 3 把锁:锁 A(仅梆梆)+ 锁 B(EULA)+ 锁 C(仅完整性报告)
 *
 * 这个 APP 只是一个 Hello World,没有任何业务逻辑,
 * 唯一目的是"被梆梆加固"后产生梆梆 so 文件(libSecShell.so 等)。
 *
 * 注意:
 *  - 加固前需在 admin-web 注册本 APP 的包名(com.xcj.bangcletest)
 *  - 加固前需配置预期签名 hash(用你将用来重签的 keystore 的签名 hash)
 *  - 梆梆加固会替换 APK 签名,加固后需用自有 keystore 重签
 *  - 重签后的 APK hash 需更新到 admin-web 白名单
 */
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val tvInfo = findViewById<TextView>(R.id.tvInfo)
        val btnCheck = findViewById<Button>(R.id.btnCheck)

        tvInfo.text = """
            梆梆加固测试 APP
            包名: ${packageName}
            版本: ${packageManager.getPackageInfo(packageName, 0).versionName}

            用途:被梆梆加固后,用小城笺"自有 APK 诊断"做梆梆自检验证
        """.trimIndent()

        btnCheck.setOnClickListener {
            tvInfo.text = """
                梆梆加固测试 APP
                包名: ${packageName}
                版本: ${packageManager.getPackageInfo(packageName, 0).versionName}
                时间: ${System.currentTimeMillis()}

                按钮点击正常(业务逻辑无问题,可加固)
            """.trimIndent()
        }
    }
}
