package com.xcj.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * 小城笺管理 + 注入 APP
 *
 * 详见 ADR 0028 (注入工具架构:安卓端 APP 上传 APK 到 SaaS 服务器注入)
 *
 * 功能:
 *  - 卡密管理(查看/禁用/解绑)
 *  - APK 注入(选择 APK 文件 -> 上传到服务器 -> 下载注入后的 APK)
 *  - 统计概览
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AppScreen()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppScreen() {
    var currentTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("卡密管理", "APK 注入", "统计")

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("小城笺管理") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            TabRow(selectedTabIndex = currentTab) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        selected = currentTab == index,
                        onClick = { currentTab = index },
                        text = { Text(title) },
                    )
                }
            }
            when (currentTab) {
                0 -> CardsManagementTab()
                1 -> ApkInjectorTab()
                2 -> StatsTab()
            }
        }
    }
}

@Composable
fun CardsManagementTab() {
    val scope = rememberCoroutineScope()
    var cards by remember { mutableStateOf<List<String>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("点击刷新加载卡密列表") }

    // 注:M3.4 简化版,用本地 token(实际需登录获取)
    val serverUrl = "http://192.168.1.3:3000"

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("卡密管理", style = MaterialTheme.typography.headlineSmall)

        Text(message, style = MaterialTheme.typography.bodyMedium)

        Button(
            onClick = {
                scope.launch {
                    loading = true
                    message = "加载中..."
                    // M3.4 简化版:API 调用预留
                    message = "卡密管理接口需登录后调用,请先在 Web 后台操作"
                    loading = false
                }
            },
            enabled = !loading,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Default.Refresh, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("刷新卡密列表")
        }

        cards.forEach { card ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(card)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = { /* 禁用 */ }) { Text("禁用") }
                        TextButton(onClick = { /* 解绑 */ }) { Text("解绑") }
                    }
                }
            }
        }
    }
}

@Composable
fun ApkInjectorTab() {
    val scope = rememberCoroutineScope()
    var apkPath by remember { mutableStateOf("") }
    var injecting by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("APK 注入", style = MaterialTheme.typography.headlineSmall)

        Text(
            "选择 APK 文件,上传到小城笺服务器注入 SDK。注入后的 APK 可用于卡密验证。",
            style = MaterialTheme.typography.bodyMedium,
        )

        OutlinedTextField(
            value = apkPath,
            onValueChange = { apkPath = it },
            label = { Text("APK 文件路径") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )

        Button(
            onClick = {
                scope.launch {
                    injecting = true
                    result = "上传中..."
                    // M3.4 简化版:注入逻辑预留
                    result = "注入功能需 SaaS 服务器支持,当前开源版请用 CLI 工具(xcj-injector.jar)"
                    injecting = false
                }
            },
            enabled = apkPath.isNotEmpty() && !injecting,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Default.Upload, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("上传并注入")
        }

        if (result.isNotEmpty()) {
            Card { Text(result, modifier = Modifier.padding(16.dp)) }
        }

        HorizontalDivider()

        Text("CLI 工具用法:", style = MaterialTheme.typography.titleMedium)
        Card {
            Text(
                """java -jar xcj-injector.jar \
  --input app.apk \
  --output app-injected.apk \
  --keystore release.keystore \
  --ks-pass xxx \
  --ks-key-alias xcj \
  --key-pass xxx \
  --watermark-id dev123""",
                modifier = Modifier.padding(16.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
fun StatsTab() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("统计概览", style = MaterialTheme.typography.headlineSmall)

        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            StatCard("应用数", "0", Icons.Default.Apps)
            StatCard("卡密总数", "0", Icons.Default.Key)
            StatCard("活跃设备", "0", Icons.Default.Devices)
        }

        Text(
            "详细统计请在 Web 管理后台查看",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
fun StatCard(label: String, value: String, icon: androidx.compose.ui.graphics.vector.ImageVector) {
    Card(modifier = Modifier.width(120.dp)) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(8.dp))
            Text(value, style = MaterialTheme.typography.headlineMedium)
            Text(label, style = MaterialTheme.typography.bodySmall)
        }
    }
}
