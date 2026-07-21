package com.xcj.app.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.xcj.app.data.prefs.TokenStore
import com.xcj.app.vm.PackerViewModel
import java.io.File
import java.io.FileOutputStream

/**
 * Packer Tab(ADR 0081,自有 APK SDK 封装器)
 *
 * 功能:
 *  - 上传 APK + Keystore + classes-xcj.dex + SDK 配置
 *  - 后端七锁校验 + 封装
 *  - 展示封装结果(taskId / 封装后 APK hash / 注入 dex hash / Keystore 指纹)
 *
 * 七锁架构(律师预审 2026-07-21 通过):
 *  锁 1 对象锁定(三重校验,后端强制)
 *  锁 2 内容锁定(固定 classes-xcj.dex 白名单,后端校验)
 *  锁 3 入口锁定(Manifest 修改范围,后端校验)
 *  锁 4 签名锁定(自备 Keystore,本 Tab 上传)
 *  锁 5 权限锁定(JWT 开发者自身,后端校验)
 *  锁 6 数据锁定(SDK 配置仅 OAID + 包信息)
 *  锁 7 客户端签名自检(后端配置预期 hash,SDK 运行时校验)
 */
@Composable
fun PackerTab(
    store: TokenStore,
) {
    val vm: PackerViewModel = viewModel(factory = packerVmFactory(store))
    val uiState by vm.uiState.collectAsState()

    var apkUri by remember { mutableStateOf<Uri?>(null) }
    var keystoreUri by remember { mutableStateOf<Uri?>(null) }
    var dexUri by remember { mutableStateOf<Uri?>(null) }
    var keystorePassword by remember { mutableStateOf("") }
    var keyAlias by remember { mutableStateOf("") }
    var keyPassword by remember { mutableStateOf("") }
    var appId by remember { mutableStateOf("") }
    var serverUrl by remember { mutableStateOf("https://xcj.winmelon.cn") }

    val context = LocalContext.current

    val apkPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> apkUri = uri }

    val keystorePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> keystoreUri = uri }

    val dexPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> dexUri = uri }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("SDK 封装", style = MaterialTheme.typography.headlineSmall)
        Text(
            "七锁架构(ADR 0081):对象/内容/入口/签名/权限/数据/客户端自检。仅限自有 APK,律师预审通过。",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // 文件选择
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("上传文件", style = MaterialTheme.typography.titleMedium)

                OutlinedButton(onClick = { apkPicker.launch("application/vnd.android.package-archive") }) {
                    Text(if (apkUri != null) "APK: ${apkUri!!.lastPathSegment}" else "选择 APK 文件")
                }
                OutlinedButton(onClick = { keystorePicker.launch("application/octet-stream") }) {
                    Text(if (keystoreUri != null) "Keystore: ${keystoreUri!!.lastPathSegment}" else "选择 Keystore(.jks/.keystore)")
                }
                OutlinedButton(onClick = { dexPicker.launch("application/octet-stream") }) {
                    Text(if (dexUri != null) "dex: ${dexUri!!.lastPathSegment}" else "选择 classes-xcj.dex")
                }
            }
        }

        // 凭证 + 配置
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Keystore 凭证 + SDK 配置", style = MaterialTheme.typography.titleMedium)

                OutlinedTextField(
                    value = keystorePassword,
                    onValueChange = { keystorePassword = it },
                    label = { Text("Keystore 密码") },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = keyAlias,
                    onValueChange = { keyAlias = it },
                    label = { Text("key 别名") },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = keyPassword,
                    onValueChange = { keyPassword = it },
                    label = { Text("key 密码") },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = appId,
                    onValueChange = { appId = it },
                    label = { Text("应用 ID(可选)") },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = serverUrl,
                    onValueChange = { serverUrl = it },
                    label = { Text("服务器 URL") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }

        // 执行按钮
        Button(
            onClick = {
                val apkFile = uriToFile(apkUri, context)
                val keystoreFile = uriToFile(keystoreUri, context)
                val dexFile = uriToFile(dexUri, context)
                if (apkFile != null && keystoreFile != null && dexFile != null) {
                    val sdkConfig = mutableMapOf<String, Any>(
                        "serverUrl" to serverUrl,
                        "offlineCacheDays" to 7,
                        "oaidEnabled" to true,
                    )
                    if (appId.isNotBlank()) sdkConfig["appId"] = appId
                    vm.pack(apkFile, keystoreFile, dexFile, keystorePassword, keyAlias, keyPassword, sdkConfig)
                }
            },
            enabled = apkUri != null && keystoreUri != null && dexUri != null &&
                    keystorePassword.isNotBlank() && keyAlias.isNotBlank() && keyPassword.isNotBlank() &&
                    uiState !is PackerViewModel.UiState.Loading,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("执行 SDK 封装(七锁校验)")
        }

        // 状态展示
        when (val state = uiState) {
            is PackerViewModel.UiState.Loading -> {
                CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
            }
            is PackerViewModel.UiState.Success -> {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("封装完成(七锁校验通过)", style = MaterialTheme.typography.titleMedium)
                        Text("taskId: ${state.result.taskId}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        Text("封装后 APK hash: ${state.result.packedApkHash}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        Text("注入 dex hash: ${state.result.injectedDexHash}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        Text("Keystore 指纹: ${state.result.keystoreFingerprint}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        Text("封装后大小: ${state.result.packedApkSize / 1024} KB", style = MaterialTheme.typography.bodySmall)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("封装后 APK 已返回(base64),可在 admin-web 或 CLI 下载。", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            is PackerViewModel.UiState.Error -> {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("错误", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(state.message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            PackerViewModel.UiState.Idle -> Unit
        }
    }
}

private fun uriToFile(uri: Uri?, context: android.content.Context): File? {
    if (uri == null) return null
    return try {
        val input = context.contentResolver.openInputStream(uri) ?: return null
        val tmpFile = File(context.cacheDir, "packer-upload-${System.currentTimeMillis()}")
        FileOutputStream(tmpFile).use { output -> input.copyTo(output) }
        input.close()
        tmpFile
    } catch (e: Exception) {
        null
    }
}

private fun packerVmFactory(store: TokenStore) = viewModelFactory {
    initializer { PackerViewModel(store = store) }
}
