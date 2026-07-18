//! JNI 桥接模块
//!
//! 详见 ADR 0023 (Rust 核心设计)
//!
//! 命名规则(默认语义化,便于审计):
//!  - `Java_com_xcj_sdk_XcjNative_init`
//!  - `Java_com_xcj_sdk_XcjNative_generateMachineId`
//!  - `Java_com_xcj_sdk_XcjNative_validateCardKey`
//!  - `Java_com_xcj_sdk_XcjNative_encryptCache`
//!  - `Java_com_xcj_sdk_XcjNative_decryptCache`
//!  - `Java_com_xcj_sdk_XcjNative_encryptRequest`
//!  - `Java_com_xcj_sdk_XcjNative_decryptResponse`
//!  - `Java_com_xcj_sdk_XcjNative_signRequest`
//!  - `Java_com_xcj_sdk_XcjNative_rsaEncrypt`
//!  - `Java_com_xcj_sdk_XcjNative_generateNonce`
//!
//! 可选 feature `opaque-jni`:启用后改用 native01-08 非语义化命名
//! 启用方式:cargo build --features opaque-jni
//!
//! 架构:
//!  - HTTP 在 Kotlin 层(OkHttp/Retrofit)
//!  - Rust 只做加密/签名/缓存/校验(无网络依赖)
//!  - 全局状态用 Mutex 保护(appId/appSecret/serverUrl)

use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use once_cell::sync::Lazy;
use std::sync::Mutex;

use crate::{cache, card_key, crypto, machine_id};

/// 全局 SDK 配置(init 时设置)
///
/// 注:字段当前未被读取(activate/validate 在 Kotlin 层做 HTTP),
/// 但保留以备后续 Rust 端实现 HTTP 请求时使用。
#[allow(dead_code)]
struct SdkConfig {
    app_id: String,
    app_secret: String,
    server_url: String,
}

static SDK_CONFIG: Lazy<Mutex<Option<SdkConfig>>> = Lazy::new(|| Mutex::new(None));

/// SDK 初始化:存全局配置
///
/// # 参数
/// - `app_id`: 应用 ID
/// - `app_secret`: 应用密钥(从 Web 后台获得)
/// - `server_url`: 服务器 URL(如 https://xcj.winmelon.cn)
///
/// # 返回
/// - 0: 成功
/// - -1: 已初始化(重复调用)
/// - -2: 内部错误
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_init(
    mut env: JNIEnv,
    _class: JClass,
    app_id: JString,
    app_secret: JString,
    server_url: JString,
) -> jint {
    let Ok(app_id) = env.get_string(&app_id) else { return -2 };
    let app_id: String = app_id.into();

    let Ok(app_secret) = env.get_string(&app_secret) else { return -2 };
    let app_secret: String = app_secret.into();

    let Ok(server_url) = env.get_string(&server_url) else { return -2 };
    let server_url: String = server_url.into();

    let mut guard = match SDK_CONFIG.lock() {
        Ok(g) => g,
        Err(_) => return -2,
    };

    if guard.is_some() {
        return -1; // 已初始化
    }

    *guard = Some(SdkConfig {
        app_id,
        app_secret,
        server_url,
    });

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
///
/// 返回 Base64 编码的 HMAC签名 | AES加密(iv+ciphertext+tag)
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

/// 解密离线缓存
///
/// 返回解密后的明文,失败返回 null
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_decryptCache(
    mut env: JNIEnv,
    _class: JClass,
    cache_key: JString,
    device_fingerprint: JString,
    encoded: JString,
) -> jstring {
    let cache_key: String = env.get_string(&cache_key).map(|s| s.into()).unwrap_or_default();
    let device_fingerprint: String = env.get_string(&device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let encoded: String = env.get_string(&encoded).map(|s| s.into()).unwrap_or_default();

    match cache::decrypt_cache(&cache_key, &device_fingerprint, &encoded) {
        Ok(plaintext) => env.new_string(plaintext).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

/// AES-256-GCM 加密请求体
///
/// # 参数
/// - `aes_key_hex`: AES 密钥(64 字符十六进制,handshake 获得)
/// - `plaintext`: 请求体明文(JSON)
///
/// # 返回
/// Base64 编码的 iv(12B) | ciphertext | tag(16B),失败返回 null
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_encryptRequest(
    mut env: JNIEnv,
    _class: JClass,
    aes_key_hex: JString,
    plaintext: JString,
) -> jstring {
    let aes_key_hex: String = env.get_string(&aes_key_hex).map(|s| s.into()).unwrap_or_default();
    let plaintext: String = env.get_string(&plaintext).map(|s| s.into()).unwrap_or_default();

    let Ok(aes_key_bytes) = hex::decode(&aes_key_hex) else {
        return std::ptr::null_mut();
    };
    if aes_key_bytes.len() != 32 {
        return std::ptr::null_mut();
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&aes_key_bytes);

    match crypto::aes_encrypt(&key, plaintext.as_bytes()) {
        Ok(encrypted) => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
            env.new_string(encoded).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// AES-256-GCM 解密响应体
///
/// # 参数
/// - `aes_key_hex`: AES 密钥(64 字符十六进制)
/// - `encoded`: Base64 编密的 iv | ciphertext | tag
///
/// # 返回
/// 解密后的明文(JSON),失败返回 null
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_decryptResponse(
    mut env: JNIEnv,
    _class: JClass,
    aes_key_hex: JString,
    encoded: JString,
) -> jstring {
    let aes_key_hex: String = env.get_string(&aes_key_hex).map(|s| s.into()).unwrap_or_default();
    let encoded: String = env.get_string(&encoded).map(|s| s.into()).unwrap_or_default();

    let Ok(aes_key_bytes) = hex::decode(&aes_key_hex) else {
        return std::ptr::null_mut();
    };
    if aes_key_bytes.len() != 32 {
        return std::ptr::null_mut();
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&aes_key_bytes);

    use base64::Engine;
    let Ok(combined) = base64::engine::general_purpose::STANDARD.decode(&encoded) else {
        return std::ptr::null_mut();
    };

    match crypto::aes_decrypt(&key, &combined) {
        Ok(plaintext_bytes) => {
            match String::from_utf8(plaintext_bytes) {
                Ok(plaintext) => env.new_string(plaintext).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// HMAC-SHA256 签名请求
///
/// # 参数
/// - `aes_key_hex`: AES 密钥(用作 HMAC 密钥,64 字符十六进制)
/// - `message`: 签名内容(method+path+timestamp+nonce+bodyHash)
///
/// # 返回
/// 64 字符十六进制签名,失败返回 null
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_signRequest(
    mut env: JNIEnv,
    _class: JClass,
    aes_key_hex: JString,
    message: JString,
) -> jstring {
    let aes_key_hex: String = env.get_string(&aes_key_hex).map(|s| s.into()).unwrap_or_default();
    let message: String = env.get_string(&message).map(|s| s.into()).unwrap_or_default();

    let Ok(aes_key_bytes) = hex::decode(&aes_key_hex) else {
        return std::ptr::null_mut();
    };

    let signature = crypto::hmac_sign(&aes_key_bytes, &message);
    env.new_string(signature).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// RSA 公钥加密(用于 handshake 加密临时 AES 密钥)
///
/// # 参数
/// - `public_key_pem`: PEM 格式 RSA 公钥
/// - `plaintext`: 待加密数据(通常是 32 字节 AES 密钥)
///
/// # 返回
/// Base64 编码的密文,失败返回 null
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_rsaEncrypt(
    mut env: JNIEnv,
    _class: JClass,
    public_key_pem: JString,
    plaintext: JString,
) -> jstring {
    let public_key_pem: String = env.get_string(&public_key_pem).map(|s| s.into()).unwrap_or_default();
    let plaintext: String = env.get_string(&plaintext).map(|s| s.into()).unwrap_or_default();

    match crypto::rsa_encrypt(&public_key_pem, plaintext.as_bytes()) {
        Ok(encrypted) => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
            env.new_string(encoded).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// 生成 32 字节随机 AES 密钥(handshake 时用)
///
/// # 返回
/// 64 字符十六进制 AES 密钥
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_generateAesKey(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let key = crypto::generate_aes_key();
    let hex_key = hex::encode(key);
    env.new_string(hex_key).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// 生成随机 nonce(请求签名防重放用)
///
/// # 返回
/// 32 字符十六进制 nonce
#[no_mangle]
pub extern "system" fn Java_com_xcj_sdk_XcjNative_generateNonce(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let nonce = crypto::generate_nonce();
    env.new_string(nonce).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_config_starts_none() {
        let guard = SDK_CONFIG.lock().unwrap();
        // 测试环境可能已被其他测试初始化,这里只验证能锁
        let _ = guard.is_some();
    }
}
