plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.xcj.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.xcj.app"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        // 服务器地址:dev 本地调试 / prod 线上
        // 实际部署时通过 -PserverUrl=xxx 注入或直接改这里
        buildConfigField("String", "SERVER_URL", "\"http://192.168.1.3:3000\"")
    }

    buildTypes {
        debug {
            // debug 用本地 IP,可被 gradle.properties 覆盖
            buildConfigField("String", "SERVER_URL", "\"http://192.168.1.3:3000\"")
        }
        release {
            isMinifyEnabled = false
            // 生产 URL 部署时注入;默认占位避免泄露真实地址
            buildConfigField("String", "SERVER_URL", "\"https://xiaochengjian.example.com\"")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-moshi:2.11.0")
    implementation("com.squareup.moshi:moshi:1.15.1")
    implementation("com.squareup.moshi:moshi-kotlin:1.15.1")
    implementation("com.jakewharton.timber:timber:5.0.1")
}
