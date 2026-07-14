# 小城笺 SDK 混淆规则
-keep class com.xcj.sdk.** { *; }
-keepclassmembers class com.xcj.sdk.XcjNative {
    public static native <methods>;
}
