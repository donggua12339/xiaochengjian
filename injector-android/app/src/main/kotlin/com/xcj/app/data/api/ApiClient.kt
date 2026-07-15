package com.xcj.app.data.api

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.xcj.app.BuildConfig
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * API 客户端单例
 *
 * - serverUrl 从 BuildConfig.SERVER_URL 读取(由 build.gradle.kts buildConfigField 注入)
 * - 调试构建打开 Timber + HttpLoggingInterceptor
 * - 60s 超时,适配弱网环境
 */
object ApiClient {

    private val moshi: Moshi = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()

    private val okHttp: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .apply {
                if (BuildConfig.DEBUG) {
                    addInterceptor(HttpLoggingInterceptor { msg ->
                        Timber.tag("XcjHttp").d(msg)
                    }.apply { level = HttpLoggingInterceptor.Level.HEADERS })
                }
            }
            .build()
    }

    val api: XcjApi by lazy {
        Retrofit.Builder()
            .baseUrl(ensureTrailingSlash(BuildConfig.SERVER_URL))
            .client(okHttp)
            .addConverterFactory(MoshiConverterFactory.create(moshi).asLenient())
            .build()
            .create(XcjApi::class.java)
    }

    /**
     * 把 Bearer 拼接好,避免每个调用点重复写
     */
    fun bearer(token: String): String = "Bearer $token"

    private fun ensureTrailingSlash(url: String): String =
        if (url.endsWith("/")) url else "$url/"
}
