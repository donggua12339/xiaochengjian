plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

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
    namespace = "com.xcj.defender.demo"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.xcj.defender.demo"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Hikari Java 字符串加密(ADR 0094):demo 模块也加密,XcjObfStr 来自 sdk AAR
    sourceSets {
        getByName("main") {
            java.setSrcDirs(listOf("build/hikari/java"))
        }
    }

    buildFeatures {
        viewBinding = false
    }

    /* X0 载荷密文(assets/xcj_payload.bin)须 STORED 不压缩,供 stub 扫 APK 魔数定位 */
    androidResources {
        noCompress += "bin"
    }

    /* X0:明文外壳 libxcj_defender.so 不打进 lib/(防静态提取),仅以密文存于 assets,
     * 运行时由 stub(xcj_loader)解密 + memfd 加载 */
    packaging {
        jniLibs {
            excludes += "**/libxcj_defender.so"
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    /* 接入真实 xcj-defender-sdk(需先编译 defender-sdk 生成 .aar) */
    implementation(files("../defender-sdk/build/outputs/aar/xcj-defender-sdk-release.aar"))
}

// === Hikari Java 字符串加密(ADR 0094) — demo 模块 ===
val hikariJavaObf by tasks.registering(Exec::class) {
    val srcDir = "src/main/java/com/xcj/defender/demo"
    val dstDir = "build/hikari/java/com/xcj/defender/demo"
    val script = "../defender-sdk/scripts/java_obf.py"
    inputs.dir(srcDir)
    outputs.dir(dstDir)
    commandLine(pythonExec, script, "--transform", srcDir, dstDir,
        "--class-name", "com.xcj.defender.XcjObfStr")
    workingDir = projectDir
}

tasks.matching { it.name.startsWith("compile") && it.name.endsWith("Kotlin") }.configureEach {
    dependsOn(hikariJavaObf)
}
