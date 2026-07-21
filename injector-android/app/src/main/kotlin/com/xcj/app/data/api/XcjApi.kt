package com.xcj.app.data.api

import com.xcj.app.data.model.ApplicationListResponse
import com.xcj.app.data.model.CardKeyDto
import com.xcj.app.data.model.CardKeyListResponse
import com.xcj.app.data.model.LoginRequest
import com.xcj.app.data.model.LoginResponse
import com.xcj.app.data.model.OperationResponse
import com.xcj.app.data.model.StatsOverview
import okhttp3.MultipartBody
import okhttp3.RequestBody
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Path
import retrofit2.http.Query
import retrofit2.http.Streaming

/**
 * 小城笺后端 API
 *
 * 路由对齐 backend/src 的控制器:
 *  - auth: /auth/login
 *  - application: /apps
 *  - card-key: /apps/{appId}/cards
 *  - stats: /developer/stats/overview
 */
interface XcjApi {

    @POST("auth/login")
    suspend fun login(@Body body: LoginRequest): Response<LoginResponse>

    @GET("apps")
    suspend fun listApps(
        @Header("Authorization") auth: String,
    ): Response<ApplicationListResponse>

    @GET("apps/{appId}/cards")
    suspend fun listCards(
        @Header("Authorization") auth: String,
        @Path("appId") appId: String,
        @Query("page") page: Int = 1,
        @Query("pageSize") pageSize: Int = 20,
    ): Response<CardKeyListResponse>

    @POST("apps/{appId}/cards/{cardId}/disable")
    suspend fun disableCard(
        @Header("Authorization") auth: String,
        @Path("appId") appId: String,
        @Path("cardId") cardId: String,
    ): Response<OperationResponse>

    @POST("apps/{appId}/cards/{cardId}/enable")
    suspend fun enableCard(
        @Header("Authorization") auth: String,
        @Path("appId") appId: String,
        @Path("cardId") cardId: String,
    ): Response<OperationResponse>

    @POST("apps/{appId}/cards/{cardId}/unbind")
    suspend fun unbindCard(
        @Header("Authorization") auth: String,
        @Path("appId") appId: String,
        @Path("cardId") cardId: String,
    ): Response<OperationResponse>

    @GET("developer/stats/overview")
    suspend fun getStatsOverview(
        @Header("Authorization") auth: String,
    ): Response<StatsOverview>

    // ============= 自有 APK 诊断(ADR 0077)=============

    /**
     * 普通诊断(只读,无加固)
     * POST /v1/audit/analyze
     */
    @Multipart
    @POST("audit/analyze")
    suspend fun analyzeApk(
        @Header("Authorization") auth: String,
        @Part apk: MultipartBody.Part,
        @Part("originalName") originalName: RequestBody,
    ): Response<ResponseBody>

    /**
     * 梆梆加固自检(ADR 0078,需先接受 EULA)
     * POST /v1/audit/analyze?hardener=bangcle
     */
    @Multipart
    @POST("audit/analyze")
    suspend fun analyzeBangcle(
        @Header("Authorization") auth: String,
        @Query("hardener") hardener: String,
        @Part apk: MultipartBody.Part,
        @Part("originalName") originalName: RequestBody,
    ): Response<ResponseBody>

    /**
     * 获取梆梆自检 EULA(锁 B 前置)
     * GET /v1/audit/eula
     */
    @GET("audit/eula")
    suspend fun getEula(
        @Header("Authorization") auth: String,
    ): Response<ResponseBody>

    /**
     * 接受梆梆自检 EULA(锁 B 前置)
     * POST /v1/audit/eula/accept
     */
    @POST("audit/eula/accept")
    suspend fun acceptEula(
        @Header("Authorization") auth: String,
        @Body body: Map<String, String>,
    ): Response<ResponseBody>

    // ============= 自有 APK SDK 封装(ADR 0081)=============

    /**
     * 执行 SDK 封装(七锁校验)
     * POST /v1/packer/pack
     */
    @Multipart
    @POST("packer/pack")
    suspend fun pack(
        @Header("Authorization") auth: String,
        @Part apk: MultipartBody.Part,
        @Part keystore: MultipartBody.Part,
        @Part xcjAuthSdkDex: MultipartBody.Part,
        @Part("keystorePassword") keystorePassword: RequestBody,
        @Part("keyAlias") keyAlias: RequestBody,
        @Part("keyPassword") keyPassword: RequestBody,
        @Part("sdkConfig") sdkConfig: RequestBody,
        @Part("originalName") originalName: RequestBody,
    ): Response<ResponseBody>

    /**
     * 查询封装历史
     * GET /v1/packer/logs
     */
    @GET("packer/logs")
    suspend fun listPackerLogs(
        @Header("Authorization") auth: String,
        @Query("limit") limit: Int = 50,
    ): Response<ResponseBody>
}
