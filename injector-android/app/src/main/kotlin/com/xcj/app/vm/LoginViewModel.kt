package com.xcj.app.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.xcj.app.data.api.ApiClient
import com.xcj.app.data.api.XcjApi
import com.xcj.app.data.model.LoginRequest
import com.xcj.app.data.model.LoginResponse
import com.xcj.app.data.prefs.TokenStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * 登录状态
 */
sealed interface LoginState {
    data object Idle : LoginState
    data object Loading : LoginState
    data class Success(val data: LoginResponse) : LoginState
    data class Error(val message: String) : LoginState
}

/**
 * 登录 ViewModel
 *
 * 登录成功后把 token 写入 TokenStore,触发全局登录态切换。
 */
class LoginViewModel(
    private val api: XcjApi = ApiClient.api,
    private val store: TokenStore,
) : ViewModel() {

    private val _state = MutableStateFlow<LoginState>(LoginState.Idle)
    val state: StateFlow<LoginState> = _state.asStateFlow()

    fun login(email: String, password: String) {
        if (email.isBlank() || password.isBlank()) {
            _state.value = LoginState.Error("邮箱和密码不能为空")
            return
        }
        _state.value = LoginState.Loading
        viewModelScope.launch {
            try {
                val resp = api.login(LoginRequest(email.trim(), password))
                if (resp.isSuccessful) {
                    val data = resp.body()!!
                    store.accessToken = data.accessToken
                    store.refreshToken = data.refreshToken
                    store.developerName = data.developer.name ?: data.developer.email
                    _state.value = LoginState.Success(data)
                } else {
                    val msg = resp.errorBody()?.string()?.take(200) ?: "登录失败(${resp.code()})"
                    _state.value = LoginState.Error(msg)
                }
            } catch (e: Exception) {
                _state.value = LoginState.Error(e.message ?: "网络异常")
            }
        }
    }
}
