//! 离线缓存加密模块(M2.7 实现)
//!
//! 详见 ADR 0026 (离线缓存加密)
//!
//! 设计:
//!  - 缓存内容:卡密、设备绑定状态、剩余有效期、上次验证时间
//!  - 加密:AES-256-GCM
//!  - 密钥派生:服务端下发 cacheKey + Rust 内 deviceFingerprint 派生最终 AES 密钥
//!  - 防篡改:缓存内容带 HMAC 签名

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::crypto;

/// 从服务端下发的 cacheKey + 设备指纹派生 AES-256 密钥
///
/// 派生算法:SHA-256(cacheKey + deviceFingerprint)[:32]
pub fn derive_cache_key(cache_key: &str, device_fingerprint: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cache_key.as_bytes());
    hasher.update(b"|");
    hasher.update(device_fingerprint.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// 加密缓存数据
///
/// # 参数
/// - `cache_key`: 服务端下发的 cacheKey
/// - `device_fingerprint`: 设备指纹
/// - `plaintext`: 缓存明文(JSON)
///
/// # 返回
/// Base64 编码的 `HMAC签名(32B) | AES加密(iv+ciphertext+tag)`
pub fn encrypt_cache(
    cache_key: &str,
    device_fingerprint: &str,
    plaintext: &str,
) -> Result<String, &'static str> {
    let aes_key = derive_cache_key(cache_key, device_fingerprint);
    let encrypted = crypto::aes_encrypt(&aes_key, plaintext.as_bytes())?;

    // HMAC 签名(用同一个派生密钥)
    let hmac_sig = crypto::hmac_sign(&aes_key, &hex::encode(&encrypted));

    let mut combined = Vec::with_capacity(64 + encrypted.len());
    combined.extend_from_slice(hmac_sig.as_bytes());
    combined.extend_from_slice(&encrypted);

    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// 解密缓存数据
///
/// # 返回
/// 解密后的明文(JSON),或错误(篡改/密钥不匹配)
pub fn decrypt_cache(
    cache_key: &str,
    device_fingerprint: &str,
    encoded: &str,
) -> Result<String, &'static str> {
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "BASE64_DECODE_FAILED")?;

    if combined.len() < 64 {
        return Err("INVALID_CACHE_FORMAT");
    }

    let (sig_bytes, encrypted) = combined.split_at(64);
    let sig = std::str::from_utf8(sig_bytes).map_err(|_| "INVALID_HMAC_ENCODING")?;

    let aes_key = derive_cache_key(cache_key, device_fingerprint);

    // 验证 HMAC
    if !crypto::hmac_verify(&aes_key, &hex::encode(encrypted), sig) {
        return Err("HMAC_VERIFICATION_FAILED");
    }

    let plaintext = crypto::aes_decrypt(&aes_key, encrypted)?;
    String::from_utf8(plaintext).map_err(|_| "UTF8_DECODE_FAILED")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cache_key = "server-issued-cache-key-123";
        let fingerprint = "device-fingerprint-abc";
        let plaintext = r#"{"cardKey":"ABCD-EFGH-IJKL-MNOP","expiresAt":"2026-07-21"}"#;

        let encrypted = encrypt_cache(cache_key, fingerprint, plaintext).unwrap();
        let decrypted = decrypt_cache(cache_key, fingerprint, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tamper_fails() {
        let cache_key = "key";
        let fingerprint = "fp";
        let encrypted = encrypt_cache(cache_key, fingerprint, "test").unwrap();

        // 篡改 Base64
        let tampered = format!("{}AA", &encrypted[..encrypted.len() - 2]);
        assert!(decrypt_cache(cache_key, fingerprint, &tampered).is_err());
    }

    #[test]
    fn test_wrong_fingerprint_fails() {
        let encrypted = encrypt_cache("key", "fp1", "test").unwrap();
        assert!(decrypt_cache("key", "fp2", &encrypted).is_err());
    }

    #[test]
    fn test_derive_key_deterministic() {
        let k1 = derive_cache_key("key", "fp");
        let k2 = derive_cache_key("key", "fp");
        assert_eq!(k1, k2);
    }
}
