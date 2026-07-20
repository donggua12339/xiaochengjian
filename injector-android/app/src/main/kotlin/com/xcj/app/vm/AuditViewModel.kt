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
 * 自有 APK 诊断 ViewModel(ADR 0077/0078)
 *
 * 功能:
 *  - 普通诊断(只读):上传 APK -> 后端三重校验 + 报告
 *  - 梆梆自检(ADR 0078):上传梆梆加固 APK -> 锁 A 检测 + 锁 C 报告
 *  - EULA 管理(锁 B 前置):获取 / 接受 EULA
 */
class AuditViewModel(
    private val store: TokenStore,
) : ViewModel() {

    private val api: XcjApi = ApiClient.api

    data class EulaInfo(
        val version: String,
        val text: String,
        val effectiveDate: String,
    )

    sealed interface UiState {
        data object Idle : UiState
        data object Loading : UiState
        data class Success(val report: String) : UiState
        data class Error(val message: String) : UiState
    }

    private val _uiState = MutableStateFlow<UiState>(UiState.Idle)
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private val _eulaInfo = MutableStateFlow<EulaInfo?>(null)
    val eulaInfo: StateFlow<EulaInfo?> = _eulaInfo.asStateFlow()

    private val _eulaAccepted = MutableStateFlow(false)
    val eulaAccepted: StateFlow<Boolean> = _eulaAccepted.asStateFlow()

    /**
     * 加载 EULA(进入梆梆自检 Tab 时调用)
     */
    fun loadEula() {
        viewModelScope.launch {
            try {
                val resp = api.getEula(ApiClient.bearer(store.accessToken ?: ""))
                if (resp.isSuccessful) {
                    val body = resp.body()?.string() ?: return@launch
                    val json = JSONObject(body)
                    _eulaInfo.value = EulaInfo(
                        version = json.optString("version"),
                        text = json.optString("text"),
                        effectiveDate = json.optString("effectiveDate"),
                    )
                    // 假设未接受,等用户点接受按钮
                    _eulaAccepted.value = false
                }
            } catch (e: Exception) {
                Timber.e(e, "loadEula failed")
            }
        }
    }

    /**
     * 接受 EULA(锁 B 前置)
     */
    fun acceptEula() {
        val info = _eulaInfo.value ?: return
        viewModelScope.launch {
            try {
                val resp = api.acceptEula(
                    ApiClient.bearer(store.accessToken ?: ""),
                    mapOf("version" to info.version),
                )
                if (resp.isSuccessful) {
                    _eulaAccepted.value = true
                }
            } catch (e: Exception) {
                Timber.e(e, "acceptEula failed")
            }
        }
    }

    /**
     * 普通诊断(只读)
     */
    fun analyzeApk(apkFile: File) {
        uploadAndAnalyze(apkFile, hardener = null)
    }

    /**
     * 梆梆加固自检(ADR 0078)
     */
    fun analyzeBangcle(apkFile: File) {
        if (!_eulaAccepted.value) {
            _uiState.value = UiState.Error("请先接受 EULA(锁 B 前置)")
            return
        }
        uploadAndAnalyze(apkFile, hardener = "bangcle")
    }

    private fun uploadAndAnalyze(apkFile: File, hardener: String?) {
        _uiState.value = UiState.Loading
        viewModelScope.launch {
            try {
                val mediaType = "application/vnd.android.package-archive".toMediaTypeOrNull()
                val apkPart = MultipartBody.Part.createFormData(
                    "apk",
                    apkFile.name,
                    apkFile.asRequestBody(mediaType),
                )
                val originalNamePart = apkFile.name.toRequestBody("text/plain".toMediaTypeOrNull())

                val resp = withContext(Dispatchers.IO) {
                    if (hardener == "bangcle") {
                        api.analyzeBangcle(
                            ApiClient.bearer(store.accessToken ?: ""),
                            "bangcle",
                            apkPart,
                            originalNamePart,
                        )
                    } else {
                        api.analyzeApk(
                            ApiClient.bearer(store.accessToken ?: ""),
                            apkPart,
                            originalNamePart,
                        )
                    }
                }

                if (resp.isSuccessful) {
                    val report = resp.body()?.string() ?: "(empty response)"
                    _uiState.value = UiState.Success(report)
                } else {
                    val errorBody = resp.errorBody()?.string()?.take(300) ?: resp.message()
                    _uiState.value = UiState.Error("HTTP ${resp.code()}: $errorBody")
                }
            } catch (e: Exception) {
                Timber.e(e, "uploadAndAnalyze failed")
                _uiState.value = UiState.Error(e.message ?: "网络错误")
            }
        }
    }

    fun reset() {
        _uiState.value = UiState.Idle
    }
}
