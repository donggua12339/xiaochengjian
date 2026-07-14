package com.xcj.demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.xcj.sdk.XcjConfig
import com.xcj.sdk.XiaochengjianSDK
import kotlinx.coroutines.launch

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
    // SDK 配置(联调时填入真实 appId + appSecret)
    val sdk = remember {
        XiaochengjianSDK(
            context,
            XcjConfig(
                appId = "8dd92267-edd6-4eee-8beb-07b0e9f46f4a",
                appSecret = "nOIaCNyEu0998CoZpD2B16MPvz3fklup",
                serverUrl = "http://localhost:8080",
            ),
        )
    }

    var cardKey by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }
    var machineId by remember { mutableStateOf("") }
    var threatLevel by remember { mutableStateOf(0) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("小城笺 SDK Demo", style = MaterialTheme.typography.headlineSmall)

        // 机器码
        Button(onClick = { machineId = sdk.generateMachineId() }) {
            Text("生成机器码")
        }
        if (machineId.isNotEmpty()) {
            Text("机器码: $machineId", style = MaterialTheme.typography.bodySmall)
        }

        // 反调试检测
        Button(onClick = { threatLevel = sdk.checkThreatLevel() }) {
            Text("反调试检测")
        }
        if (threatLevel > 0) {
            val msg = when (threatLevel) {
                1 -> "检测到调试器!"
                2 -> "检测到模拟器!"
                else -> "未知威胁"
            }
            Text(msg, color = MaterialTheme.colorScheme.error)
        } else if (threatLevel == 0) {
            // 初始状态不显示
        }

        HorizontalDivider()

        // 卡密输入
        OutlinedTextField(
            value = cardKey,
            onValueChange = { cardKey = it.uppercase() },
            label = { Text("卡密(如 ABCD-EFGH-IJKL-MNOP)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )

        // 格式校验
        val formatValid = if (cardKey.isNotEmpty()) sdk.validateCardKeyFormat(cardKey) else null
        if (formatValid != null) {
            Text(
                if (formatValid) "格式正确" else "格式错误",
                color = if (formatValid) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            )
        }

        // 激活
        Button(
            onClick = {
                scope.launch {
                    val r = sdk.activate(cardKey)
                    result = if (r.success) {
                        "激活成功:类型=${r.cardKeyType}, 过期=${r.expiresAt}"
                    } else {
                        "激活失败:${r.errorMessage}"
                    }
                }
            },
            enabled = cardKey.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("激活卡密")
        }

        // 验证
        Button(
            onClick = {
                scope.launch {
                    val r = sdk.validate(cardKey)
                    result = if (r.success) {
                        "验证成功:过期=${r.expiresAt}"
                    } else {
                        "验证失败:${r.errorMessage}"
                    }
                }
            },
            enabled = cardKey.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("验证卡密")
        }

        if (result.isNotEmpty()) {
            Card {
                Text(result, modifier = Modifier.padding(16.dp))
            }
        }
    }
}
