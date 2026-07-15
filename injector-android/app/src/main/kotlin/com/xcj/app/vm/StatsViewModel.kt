package com.xcj.app.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.xcj.app.data.api.ApiClient
import com.xcj.app.data.api.XcjApi
import com.xcj.app.data.model.StatsOverview
import com.xcj.app.data.prefs.TokenStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * 统计 Tab UI 状态
 */
data class StatsUiState(
    val loading: Boolean = false,
    val stats: StatsOverview = StatsOverview(),
    val error: String? = null,
)

/**
 * 统计 ViewModel
 *
 * 调 /developer/stats/overview 拉取开发者级聚合统计
 */
class StatsViewModel(
    private val api: XcjApi = ApiClient.api,
    private val store: TokenStore,
) : ViewModel() {

    private val _state = MutableStateFlow(StatsUiState(loading = true))
    val state: StateFlow<StatsUiState> = _state.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        val token = store.accessToken ?: run {
            _state.value = _state.value.copy(loading = false, error = "未登录")
            return
        }
        _state.value = _state.value.copy(loading = true, error = null)
        viewModelScope.launch {
            try {
                val resp = api.getStatsOverview(ApiClient.bearer(token))
                if (resp.isSuccessful) {
                    _state.value = _state.value.copy(
                        loading = false,
                        stats = resp.body() ?: StatsOverview(),
                    )
                } else {
                    _state.value = _state.value.copy(
                        loading = false,
                        error = "加载失败(${resp.code()})",
                    )
                }
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    loading = false,
                    error = e.message ?: "网络异常",
                )
            }
        }
    }
}
