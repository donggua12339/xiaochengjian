package com.xcj.app.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.xcj.app.data.api.ApiClient
import com.xcj.app.data.api.XcjApi
import com.xcj.app.data.prefs.TokenStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import timber.log.Timber
import java.io.File

/**
 * Packer ViewModel(ADR 0081,自有 APK SDK 封装器)
 *
 * 功能:
 *  - 封装:上传 APK + Keystore + classes-xcj.dex -> 七锁校验 -> 返回封装后 APK
 *  - 历史:查询封装记录
 */
class PackerViewModel(
    private val store: TokenStore,
) : ViewModel() {

    private val api: XcjApi = ApiClient.api

    data class PackResult(
        val taskId: String,
        val packedApkHash: String,
        val injectedDexHash: String,
        val keystoreFingerprint: String,
        val packedApkBase64: String,
        val packedApkSize: Int,
    )

    sealed interface UiState {
        data object Idle : UiState
        data object Loading : UiState
        data class Success(val result: PackResult) : UiState
        data class Error(val message: String) : UiState
    }

    private val _uiState = MutableStateFlow<UiState>(UiState.Idle)
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private val _historyJson = MutableStateFlow<String?>(null)
    val historyJson: StateFlow<String?> = _historyJson.asStateFlow()

    /**
     * 执行封装
     */
    fun pack(
        apkFile: File,
        keystoreFile: File,
        xcjAuthSdkDexFile: File,
        keystorePassword: String,
        keyAlias: String,
        keyPassword: String,
        sdkConfig: Map<String, Any>,
    ) {
        _uiState.value = UiState.Loading
        viewModelScope.launch {
            try {
                val apkPart = MultipartBody.Part.createFormData(
                    "apk", apkFile.name, apkFile.asRequestBody("application/vnd.android.package-archive".toMediaTypeOrNull()),
                )
                val keystorePart = MultipartBody.Part.createFormData(
                    "keystore", keystoreFile.name, keystoreFile.asRequestBody("application/octet-stream".toMediaTypeOrNull()),
                )
                val dexPart = MultipartBody.Part.createFormData(
                    "xcjAuthSdkDex", xcjAuthSdkDexFile.name, xcjAuthSdkDexFile.asRequestBody("application/octet-stream".toMediaTypeOrNull()),
                )
                val ksPassBody = keystorePassword.toRequestBody("text/plain".toMediaTypeOrNull())
                val keyAliasBody = keyAlias.toRequestBody("text/plain".toMediaTypeOrNull())
                val keyPassBody = keyPassword.toRequestBody("text/plain".toMediaTypeOrNull())
                val sdkConfigBody = JSONObject(sdkConfig).toString().toRequestBody("application/json".toMediaTypeOrNull())
                val originalNameBody = apkFile.name.toRequestBody("text/plain".toMediaTypeOrNull())

                val resp = withContext(Dispatchers.IO) {
                    api.pack(
                        ApiClient.bearer(store.accessToken ?: ""),
                        apkPart, keystorePart, dexPart,
                        ksPassBody, keyAliasBody, keyPassBody, sdkConfigBody, originalNameBody,
                    )
                }

                if (resp.isSuccessful) {
                    val body = resp.body()?.string() ?: ""
                    val json = JSONObject(body)
                    val result = PackResult(
                        taskId = json.optString("taskId"),
                        packedApkHash = json.optString("packedApkHash"),
                        injectedDexHash = json.optString("injectedDexHash"),
                        keystoreFingerprint = json.optString("keystoreFingerprint"),
                        packedApkBase64 = json.optString("packedApkBase64"),
                        packedApkSize = json.optInt("packedApkSize"),
                    )
                    _uiState.value = UiState.Success(result)
                } else {
                    val errorBody = resp.errorBody()?.string()?.take(300) ?: resp.message()
                    _uiState.value = UiState.Error("HTTP ${resp.code()}: $errorBody")
                }
            } catch (e: Exception) {
                Timber.e(e, "pack failed")
                _uiState.value = UiState.Error(e.message ?: "网络错误")
            }
        }
    }

    /**
     * 查询封装历史
     */
    fun loadHistory() {
        viewModelScope.launch {
            try {
                val resp = withContext(Dispatchers.IO) {
                    api.listPackerLogs(ApiClient.bearer(store.accessToken ?: ""))
                }
                if (resp.isSuccessful) {
                    _historyJson.value = resp.body()?.string()
                }
            } catch (e: Exception) {
                Timber.e(e, "loadHistory failed")
            }
        }
    }

    fun reset() {
        _uiState.value = UiState.Idle
    }
}
