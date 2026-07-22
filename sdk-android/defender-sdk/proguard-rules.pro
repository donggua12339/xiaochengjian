# xcj-defender-sdk ProGuard Rules

# 保留 JNI native 方法(否则找不到 C 函数)
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留 ContentProvider(系统反射创建)
-keep class com.xcj.defender.DefenderInitProvider { *; }

# 保留 DefenderNative(JNI 声明)
-keep class com.xcj.defender.DefenderNative { *; }

# 保留 DefenderConfig(JSON 反序列化)
-keep class com.xcj.defender.DefenderConfig { *; }
-keep class com.xcj.defender.DefenderConfig$* { *; }
