package com.xcj.demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
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

    // SDK 配置(联调时填入真实值)
    val sdk = remember {
        XiaochengjianSDK(
            context,
            SdkConfig(
                appId = "your-app-id",
                appSecret = "your-app-secret",
                serverUrl = "https://xcj.winmelon.cn",
                serverPublicKeyPem = """
                    -----BEGIN PUBLIC KEY-----
                    YOUR_SERVER_RSA_PUBLIC_KEY_HERE
                    -----END PUBLIC KEY-----
                """.trimIndent(),
            ),
        )
    }

    var cardKey by remember { mutableStateOf("") }
    var machineId by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }

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
                    val r = sdk.activate(cardKey)
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
