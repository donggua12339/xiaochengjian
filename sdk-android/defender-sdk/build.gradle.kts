plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.xcj.defender"
    compileSdk = 35

    defaultConfig {
        minSdk = 24

        // 仅支持 arm64-v8a + armeabi-v7a(覆盖 99% 设备)
        // x86/x86_64 不支持(模拟器检测会拦截)
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }

        externalNativeBuild {
            cmake {
                // C 编译
                cppFlags("")
                cFlags(
                    "-O2",
                    "-fvisibility=hidden",
                    "-ffunction-sections",
                    "-fdata-sections",
                    "-Wall",
                    "-Wno-unused-parameter"
                )
                // 传递版本号给 C 代码
                arguments("-DDEFENDER_VERSION=\\\"1.0.0\\\"")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
    /* Play Integrity API(2026 服务端信任验证,需 Google Play 服务) */
    implementation("com.google.android.play:integrity:1.4.0")
}
