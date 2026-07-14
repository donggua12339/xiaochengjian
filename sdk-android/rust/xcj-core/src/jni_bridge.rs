//! JNI 桥接模块
//!
//! 详见 ADR 0023 (Rust 核心设计:JNI 函数名非语义化)
//!
//! 命名规则:`Java_com_xcj_sdk_XcjNative_nativeNN`(native01-native08)
//! - 非语义化,提升逆向难度
//! - 不用下划线(JNI 会把 _ 编码为 _1,导致名称不匹配)

use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;

use crate::{anti_debug, cache, card_key, machine_id};

/// native01: 初始化 SDK
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_native01(
    _env: JNIEnv,
    _class: JClass,
    _app_id: JString,
    _app_secret: JString,
    _server_url: JString,
) -> jint {
    0
}

/// native02: 生成机器码
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_native02(
    mut env: JNIEnv,
    _class: JClass,
    android_id: JString,
    media_drm_id: JString,
    hardware_fingerprint: JString,
) -> jstring {
    let android_id: String = env.get_string(&android_id).map(|s| s.into()).unwrap_or_default();
    let media_drm_id: Option<String> = env
        .get_string(&media_drm_id)
        .ok()
        .map(|s| s.into())
        .filter(|s: &String| !s.is_empty());
    let hardware_fingerprint: String = env
        .get_string(&hardware_fingerprint)
        .map(|s| s.into())
        .unwrap_or_default();

    let machine_id = machine_id::generate_machine_id(&android_id, media_drm_id.as_deref(), &hardware_fingerprint);

    env.new_string(machine_id)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// native03: 校验卡密格式(1=合法,0=非法)
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_native03(
    mut env: JNIEnv,
    _class: JClass,
    card_key: JString,
) -> jint {
    let card_key: String = env.get_string(&card_key).map(|s| s.into()).unwrap_or_default();
    if card_key::validate_card_key(&card_key) { 1 } else { 0 }
}

/// native06: 反调试检测(0=Clean,1=Debug,2=Emulator)
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_native06(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let result = anti_debug::detect();
    match result.level {
        anti_debug::ThreatLevel::Clean => 0,
        anti_debug::ThreatLevel::DebugDetected => 1,
        anti_debug::ThreatLevel::EmulatorDetected => 2,
    }
}

/// native08: 加密离线缓存
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_native08(
    mut env: JNIEnv,
    _class: JClass,
    cache_key: JString,
    device_fingerprint: JString,
    plaintext: JString,
) -> jstring {
    let cache_key: String = env.get_string(&cache_key).map(|s| s.into()).unwrap_or_default();
    let device_fingerprint: String = env.get_string(&device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let plaintext: String = env.get_string(&plaintext).map(|s| s.into()).unwrap_or_default();

    match cache::encrypt_cache(&cache_key, &device_fingerprint, &plaintext) {
        Ok(encoded) => env.new_string(encoded).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}
