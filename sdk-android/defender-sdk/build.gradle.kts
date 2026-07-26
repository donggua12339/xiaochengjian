plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

// 构建期跑 X1 字符串混淆脚本 obfstr_poly.py 用的 Python 解释器。
// NDK 的 CMake find_package(Python3) 在本机失败(WindowsApps 的 python3 是残桩),
// 故由 Gradle 探测一个能跑的 python 并显式传给 CMake。可用 -PxcjPythonExec=... 覆盖。
val pythonExec: String = (providers.gradleProperty("xcjPythonExec").orNull) ?: run {
    try {
        val proc = ProcessBuilder("python", "-c", "import sys; print(sys.executable)")
            .redirectErrorStream(true).start()
        val path = proc.inputStream.bufferedReader().readText().trim()
        proc.waitFor()
        path.replace("\\", "/").ifEmpty { "python" }
    } catch (e: Exception) {
        "python"
    }
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
                arguments(
                    "-DDEFENDER_VERSION=\\\"1.0.0\\\"",
                    "-DPython3_EXECUTABLE=$pythonExec",
                )
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

    // Hikari Java 字符串加密(ADR 0094):构建期变换源码,JADX 静态搜索失效。
    // 构建用 build/hikari/java(变换后),IDE 用 src/main/java(原始)。
    sourceSets {
        getByName("main") {
            java.setSrcDirs(listOf("build/hikari/java"))
        }
    }
}

// === Hikari Java 字符串加密任务(ADR 0094)== =
val hikariJavaObf by tasks.registering(Exec::class) {
    val srcDir = "src/main/java/com/xcj/defender"
    val dstDir = "build/hikari/java/com/xcj/defender"
    val script = "scripts/java_obf.py"
    inputs.dir(srcDir)
    outputs.dir(dstDir)
    commandLine(pythonExec, script, "--all", srcDir, dstDir)
    workingDir = projectDir
}

// 编译前跑 Hikari 变换
tasks.matching { it.name.startsWith("compile") && it.name.endsWith("Kotlin") }.configureEach {
    dependsOn(hikariJavaObf)
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
    /* Play Integrity API(2026 服务端信任验证,需 Google Play 服务) */
    implementation("com.google.android.play:integrity:1.4.0")
}
