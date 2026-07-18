package com.xcj.demo

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.xcj.sdk.SdkConfig
import com.xcj.sdk.XiaochengjianSDK
import kotlinx.coroutines.launch

/**
 * 小城笺 SDK Demo APP
 *
 * 演示完整流程:
 *  1. 初始化 SDK(填入 appId/appSecret/serverUrl/serverPublicKeyPem)
 *  2. 生成机器码
 *  3. 校验卡密格式(本地)
 *  4. 激活卡密(网络请求:handshake + AES 加密 + HMAC 签名)
 *  5. 验证卡密(网络请求 + 离线缓存)
 *
 * 注:联调时需要填入真实的 appId/appSecret/serverPublicKeyPem
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DemoScreen()
                }
            }
        }
    }
}

@Composable
fun DemoScreen() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()

    // SDK 配置(已填入真实值,用于端到端联调)
    val sdk = remember {
        XiaochengjianSDK(
            context,
            SdkConfig(
                appId = "f960c304-f61d-4f1f-b297-3f48fcc90b35",
                appSecret = "w7Vnw74on2rPEKATG80Cc6fW1mx35i8r",
                serverUrl = "https://xcj.winmelon.cn",
                serverPublicKeyPem = """
                    -----BEGIN PUBLIC KEY-----
                    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Y2vNIf/mVb1JkYlStFa
                    hYIn/LA81mMGCW2anFRA8oJhmw0G3B1K1IMNrHXPmfUx2CHJyEGxWYNTZVBsU1f2
                    M1NZBLjsJ35jfihDs9OpPOvi6a6C+i6rv8v5djOvStCBK2ezO6TY4hE3mq1VAsWJ
                    THtsdCYKYP1JahXrIcQCdgb4fmZ8qak1b6jMcqwY0Bmy1juU5YS9ZOoHbd+uIKQE
                    Q/3fBXwRu2tRzgzk4c8DVPgRSo2knQ9qN0PTx3FIUWIvG9qOMPPmWgjVY9jRdLBg
                    GhTZVZI0lsmlWaVvLFMpmDpCexQUMWp0Us5cbdHDYCsvGqcklVlhz6QT4dqcnMMV
                    JQIDAQAB
                    -----END PUBLIC KEY-----
                """.trimIndent(),
            ),
        )
    }

    var cardKey by remember { mutableStateOf("9EXH-7MP3-BXD9-4CX3") }
    var machineId by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }

    // 启动时自动测试完整流程
    LaunchedEffect(Unit) {
        Log.i("XcjDemo", "=== 自动测试开始 ===")
        // 1. 生成机器码
        machineId = sdk.generateMachineId()
        Log.i("XcjDemo", "机器码: $machineId")
        // 2. 格式校验
        val formatOk = sdk.validateCardKeyFormat(cardKey)
        Log.i("XcjDemo", "卡密格式校验: $formatOk")
        // 3. 激活
        val activateResult = sdk.activate(cardKey)
        Log.i("XcjDemo", "激活结果: success=${activateResult.success}, cardType=${activateResult.cardType}, expiresAt=${activateResult.expiresAt}, reason=${activateResult.reason}")
        // 4. 验证
        val validateResult = sdk.validate(cardKey)
        Log.i("XcjDemo", "验证结果: success=${validateResult.success}, valid=${validateResult.valid}, expiresAt=${validateResult.expiresAt}, reason=${validateResult.reason}, cached=${validateResult.cached}")
        result = if (activateResult.success) {
            "✓ 激活成功\n类型: ${activateResult.cardType}\n过期: ${activateResult.expiresAt}"
        } else {
            "✗ 激活失败: ${activateResult.reason}"
        }
        Log.i("XcjDemo", "=== 自动测试结束 ===")
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("小城笺 SDK Demo", style = MaterialTheme.typography.headlineSmall)

        // 1. 生成机器码
        Button(onClick = { machineId = sdk.generateMachineId() }, modifier = Modifier.fillMaxWidth()) {
            Text("生成机器码")
        }
        if (machineId.isNotEmpty()) {
            Text("机器码: $machineId", style = MaterialTheme.typography.bodySmall)
        }

        HorizontalDivider()

        // 2. 卡密输入
        OutlinedTextField(
            value = cardKey,
            onValueChange = { cardKey = it.uppercase() },
            label = { Text("卡密(如 ABCD-EFGH-IJKL-MNOP)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )

        // 3. 格式校验(本地)
        val formatValid = if (cardKey.isNotEmpty()) sdk.validateCardKeyFormat(cardKey) else null
        if (formatValid != null) {
            Text(
                if (formatValid) "✓ 格式正确" else "✗ 格式错误",
                color = if (formatValid) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            )
        }

        // 4. 激活
        Button(
            onClick = {
                scope.launch {
                    Log.i("XcjDemo", "激活按钮点击,cardKey=$cardKey")
                    val r = sdk.activate(cardKey)
                    Log.i("XcjDemo", "激活结果:success=${r.success},reason=${r.reason},cardType=${r.cardType},expiresAt=${r.expiresAt}")
                    result = if (r.success) {
                        "✓ 激活成功\n类型: ${r.cardType}\n过期: ${r.expiresAt}\n缓存天数: ${r.offlineCacheDays}"
                    } else {
                        "✗ 激活失败: ${r.reason}"
                    }
                }
            },
            enabled = cardKey.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("激活卡密(网络)")
        }

        // 5. 验证
        Button(
            onClick = {
                scope.launch {
                    val r = sdk.validate(cardKey)
                    result = if (r.success) {
                        if (r.valid) {
                            "✓ 验证通过\n过期: ${r.expiresAt}\n缓存: ${if (r.cached) "是(离线)" else "否(在线)"}"
                        } else {
                            "✗ 验证失败: ${r.reason}"
                        }
                    } else {
                        "✗ 请求失败: ${r.reason}"
                    }
                }
            },
            enabled = cardKey.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("验证卡密(网络 + 离线缓存)")
        }

        if (result.isNotEmpty()) {
            Card {
                Text(result, modifier = Modifier.padding(16.dp))
            }
        }
    }
}
