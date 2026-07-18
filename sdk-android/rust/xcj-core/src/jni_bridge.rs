//! JNI 桥接模块
//!
//! 详见 ADR 0023 (Rust 核心设计)
//!
//! 命名规则(默认语义化,便于审计):
//!  - `Java_com_xcj_sdk_XcjNative_init`
//!  - `Java_com_xcj_sdk_XcjNative_activate`
//!  - `Java_com_xcj_sdk_XcjNative_validate`
//!  - `Java_com_xcj_sdk_XcjNative_heartbeat`
//!  - `Java_com_xcj_sdk_XcjNative_generateMachineId`
//!  - `Java_com_xcj_sdk_XcjNative_validateCardKey`
//!  - `Java_com_xcj_sdk_XcjNative_encryptCache`
//!  - `Java_com_xcj_sdk_XcjNative_decryptCache`
//!
//! 可选 feature `opaque-jni`:启用后改用 native01-08 非语义化命名
//! 启用方式:cargo build --features opaque-jni
//!
//! 注:不用下划线(JNI 会把 _ 编码为 _1,导致名称不匹配)

use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;

use crate::{cache, card_key, machine_id};

// ============= 语义化命名(默认) =============

/// SDK 初始化(Day 5 实现)
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_init(
    _env: JNIEnv,
    _class: JClass,
    _app_id: JString,
    _app_secret: JString,
    _server_url: JString,
) -> jint {
    // TODO Day 5:实现真实初始化(存全局状态)
    0
}

/// 生成机器码
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_generateMachineId(
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

/// 校验卡密格式(1=合法,0=非法)
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_validateCardKey(
    mut env: JNIEnv,
    _class: JClass,
    card_key: JString,
) -> jint {
    let card_key: String = env.get_string(&card_key).map(|s| s.into()).unwrap_or_default();
    if card_key::validate_card_key(&card_key) { 1 } else { 0 }
}

/// 加密离线缓存
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_encryptCache(
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

// TODO Day 5:实现 activate / validate / heartbeat / decryptCache
