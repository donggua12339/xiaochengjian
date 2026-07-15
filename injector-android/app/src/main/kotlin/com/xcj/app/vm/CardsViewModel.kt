package com.xcj.app.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.xcj.app.data.api.ApiClient
import com.xcj.app.data.api.XcjApi
import com.xcj.app.data.model.ApplicationDto
import com.xcj.app.data.model.CardKeyDto
import com.xcj.app.data.prefs.TokenStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * 卡密管理 UI 状态
 */
data class CardsUiState(
    val loading: Boolean = false,
    val apps: List<ApplicationDto> = emptyList(),
    val currentApp: ApplicationDto? = null,
    val cards: List<CardKeyDto> = emptyList(),
    val total: Long = 0,
    val message: String? = null,
    val error: String? = null,
)

/**
 * 卡密管理 ViewModel
 *
 * - 首次进入加载应用列表,默认选中第一个
 * - 选中应用后加载卡密列表
 * - 支持禁用 / 启用 / 解绑操作
 */
class CardsViewModel(
    private val api: XcjApi = ApiClient.api,
    private val store: TokenStore,
) : ViewModel() {

    private val _state = MutableStateFlow(CardsUiState(loading = true))
    val state: StateFlow<CardsUiState> = _state.asStateFlow()

    private val token: String? get() = store.accessToken
    private fun auth(): String? = token?.let { ApiClient.bearer(it) }

    init {
        loadInitial()
    }

    private fun loadInitial() {
        viewModelScope.launch {
            try {
                val apps = safeCall { api.listApps(requireNotNull(auth())) }
                val list = apps?.items ?: emptyList()
                val current = list.firstOrNull { it.id == store.currentAppId } ?: list.firstOrNull()
                store.currentAppId = current?.id
                _state.value = _state.value.copy(
                    loading = false,
                    apps = list,
                    currentApp = current,
                )
                if (current != null) loadCards(current.id)
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    loading = false,
                    error = e.message ?: "加载应用失败",
                )
            }
        }
    }

    fun selectApp(appId: String) {
        val app = _state.value.apps.firstOrNull { it.id == appId } ?: return
        store.currentAppId = appId
        _state.value = _state.value.copy(currentApp = app, cards = emptyList(), total = 0)
        loadCards(appId)
    }

    fun refresh() {
        val appId = _state.value.currentApp?.id ?: return
        loadCards(appId)
    }

    private fun loadCards(appId: String) {
        _state.value = _state.value.copy(loading = true, error = null)
        viewModelScope.launch {
            try {
                val result = safeCall { api.listCards(requireNotNull(auth()), appId) }
                _state.value = _state.value.copy(
                    loading = false,
                    cards = result?.items ?: emptyList(),
                    total = result?.total ?: 0,
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    loading = false,
                    error = e.message ?: "加载卡密失败",
                )
            }
        }
    }

    fun disable(cardId: String) {
        val appId = _state.value.currentApp?.id ?: return
        act(appId, cardId) { api.disableCard(requireNotNull(auth()), appId, cardId) }
    }

    fun enable(cardId: String) {
        val appId = _state.value.currentApp?.id ?: return
        act(appId, cardId) { api.enableCard(requireNotNull(auth()), appId, cardId) }
    }

    fun unbind(cardId: String) {
        val appId = _state.value.currentApp?.id ?: return
        act(appId, cardId) { api.unbindCard(requireNotNull(auth()), appId, cardId) }
    }

    private fun act(appId: String, cardId: String, block: suspend () -> retrofit2.Response<com.xcj.app.data.model.OperationResponse>) {
        _state.value = _state.value.copy(message = null, error = null)
        viewModelScope.launch {
            try {
                val resp = block()
                _state.value = _state.value.copy(
                    message = if (resp.isSuccessful) "操作成功" else "操作失败(${resp.code()})",
                )
                loadCards(appId)
            } catch (e: Exception) {
                _state.value = _state.value.copy(error = e.message ?: "操作异常")
            }
        }
    }

    private fun logout() {
        store.clear()
    }
}

/**
 * 把 Retrofit 响应解包;失败时抛 IllegalStateException 带 code + body 摘要
 */
private suspend fun <T> safeCall(block: suspend () -> retrofit2.Response<T>): T? {
    val resp = block()
    return if (resp.isSuccessful) {
        resp.body()
    } else {
        val msg = resp.errorBody()?.string()?.take(200) ?: "HTTP ${resp.code()}"
        throw IllegalStateException(msg)
    }
}
