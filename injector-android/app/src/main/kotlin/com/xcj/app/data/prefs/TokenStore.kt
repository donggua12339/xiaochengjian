package com.xcj.app.data.prefs

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * 加密存储 accessToken / refreshToken / 当前选中的 appId
 *
 * 使用 EncryptedSharedPreferences(AES256-GCM),
 * 密钥由 Android Keystore 派生,不会落盘明文。
 */
class TokenStore(context: Context) {

    private val prefs by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            context,
            FILE_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    var accessToken: String?
        get() = prefs.getString(KEY_ACCESS_TOKEN, null)
        set(value) = prefs.edit().putString(KEY_ACCESS_TOKEN, value).apply()

    var refreshToken: String?
        get() = prefs.getString(KEY_REFRESH_TOKEN, null)
        set(value) = prefs.edit().putString(KEY_REFRESH_TOKEN, value).apply()

    var currentAppId: String?
        get() = prefs.getString(KEY_CURRENT_APP_ID, null)
        set(value) = prefs.edit().putString(KEY_CURRENT_APP_ID, value).apply()

    var developerName: String?
        get() = prefs.getString(KEY_DEV_NAME, null)
        set(value) = prefs.edit().putString(KEY_DEV_NAME, value).apply()

    fun clear() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val FILE_NAME = "xcj_auth"
        private const val KEY_ACCESS_TOKEN = "access_token"
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_CURRENT_APP_ID = "current_app_id"
        private const val KEY_DEV_NAME = "dev_name"
    }
}
