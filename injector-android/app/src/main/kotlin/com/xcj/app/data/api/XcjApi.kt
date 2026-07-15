package com.xcj.app.data.api

import com.xcj.app.data.model.ApplicationListResponse
import com.xcj.app.data.model.CardKeyDto
import com.xcj.app.data.model.CardKeyListResponse
import com.xcj.app.data.model.LoginRequest
import com.xcj.app.data.model.LoginResponse
import com.xcj.app.data.model.OperationResponse
import com.xcj.app.data.model.StatsOverview
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

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
}
