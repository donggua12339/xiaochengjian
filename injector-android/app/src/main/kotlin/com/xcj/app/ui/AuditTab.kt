package com.xcj.app.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.xcj.app.data.prefs.TokenStore
import com.xcj.app.vm.AuditViewModel
import java.io.File
import java.io.FileOutputStream

/**
 * 自有 APK 诊断 Tab(ADR 0077/0078)
 *
 * 两个子区域:
 *  - 普通诊断(只读):上传自有 APK -> 后端三重校验 + 报告
 *  - 梆梆自检(ADR 0078):上传梆梆加固 APK -> 锁 A 检测 + 锁 C 报告
 *    需先接受 EULA(锁 B 前置)
 *
 * 三重校验在后端执行,本 Tab 不绕过。
 */
@Composable
fun AuditTab(
    store: TokenStore,
) {
    val vm: AuditViewModel = viewModel(factory = auditVmFactory(store))
    val uiState by vm.uiState.collectAsState()
    val eulaInfo by vm.eulaInfo.collectAsState()
    val eulaAccepted by vm.eulaAccepted.collectAsState()

    var selectedApkUri by remember { mutableStateOf<Uri?>(null) }
    var showEulaDialog by remember { mutableStateOf(false) }
    val context = LocalContext.current

    // 进入时加载 EULA
    androidx.compose.runtime.LaunchedEffect(Unit) {
        vm.loadEula()
    }

    val apkPickerLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri ->
        selectedApkUri = uri
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("自有 APK 诊断", style = MaterialTheme.typography.headlineSmall)
        Text(
            "三重校验(包名白名单 + 签名 hash 比对 + 目录隔离)在后端执行,本工具不绕过。",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // ========== 普通诊断 ==========
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("普通诊断(只读)", style = MaterialTheme.typography.titleMedium)
                Text(
                    "上传自有 APK -> 后端 JADX 查看 + 签名信息 + SDK 后门扫描(不脱壳不反编译)",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                ApkPickerButton(
                    selectedUri = selectedApkUri,
                    onPick = { apkPickerLauncher.launch("application/vnd.android.package-archive") },
                )
                Button(
                    onClick = {
                        selectedApkUri?.let { uri ->
                            val file = uriToFile(uri, context)
                            if (file != null) vm.analyzeApk(file)
                        }
                    },
                    enabled = selectedApkUri != null && uiState !is AuditViewModel.UiState.Loading,
                ) {
                    Text("开始诊断")
                }
            }
        }

        // ========== 梆梆自检 ==========
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("梆梆加固自检(ADR 0078)", style = MaterialTheme.typography.titleMedium)
                Text(
                    "锁 A(仅梆梆)+ 锁 B(EULA 前置)+ 锁 C(仅完整性报告,不输出源码)",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                if (eulaInfo != null && !eulaAccepted) {
                    OutlinedButton(onClick = { showEulaDialog = true }) {
                        Text("查看并接受 EULA(锁 B 前置)")
                    }
                } else if (eulaAccepted) {
                    Text(
                        "✓ EULA v${eulaInfo?.version} 已接受,可执行梆梆自检",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }

                ApkPickerButton(
                    selectedUri = selectedApkUri,
                    onPick = { apkPickerLauncher.launch("application/vnd.android.package-archive") },
                )
                Button(
                    onClick = {
                        selectedApkUri?.let { uri ->
                            val file = uriToFile(uri, context)
                            if (file != null) vm.analyzeBangcle(file)
                        }
                    },
                    enabled = selectedApkUri != null && eulaAccepted && uiState !is AuditViewModel.UiState.Loading,
                ) {
                    Text("执行梆梆自检")
                }
            }
        }

        // ========== 状态展示 ==========
        when (val state = uiState) {
            is AuditViewModel.UiState.Loading -> {
                Box(modifier = Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            }
            is AuditViewModel.UiState.Success -> {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("诊断报告", style = MaterialTheme.typography.titleMedium)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = state.report,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFF5F5F5), RoundedCornerShape(4.dp))
                                .padding(8.dp),
                        )
                    }
                }
            }
            is AuditViewModel.UiState.Error -> {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("错误", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = state.message,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
            AuditViewModel.UiState.Idle -> Unit
        }
    }

    // EULA 弹窗(锁 B)
    if (showEulaDialog && eulaInfo != null) {
        AlertDialog(
            onDismissRequest = { showEulaDialog = false },
            title = { Text("梆梆加固自检 EULA v${eulaInfo!!.version}") },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    Text("生效日期:${eulaInfo!!.effectiveDate}")
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(eulaInfo!!.text, style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    vm.acceptEula()
                    showEulaDialog = false
                }) {
                    Text("我已阅读并接受")
                }
            },
            dismissButton = {
                TextButton(onClick = { showEulaDialog = false }) {
                    Text("取消")
                }
            },
        )
    }
}

@Composable
private fun ApkPickerButton(selectedUri: Uri?, onPick: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        OutlinedButton(onClick = onPick) {
            Text(if (selectedUri != null) "已选择 APK,点击重新选择" else "选择 APK 文件")
        }
        selectedUri?.let {
            Text(
                "已选:${it.lastPathSegment ?: it.toString()}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * Uri 转 File(复制到 cacheDir)
 */
private fun uriToFile(uri: Uri, context: android.content.Context): File? {
    return try {
        val input = context.contentResolver.openInputStream(uri) ?: return null
        val tmpFile = File(context.cacheDir, "audit-upload-${System.currentTimeMillis()}.apk")
        FileOutputStream(tmpFile).use { output ->
            input.copyTo(output)
        }
        input.close()
        tmpFile
    } catch (e: Exception) {
        null
    }
}

private fun auditVmFactory(store: TokenStore) = viewModelFactory {
    initializer { AuditViewModel(store = store) }
}
