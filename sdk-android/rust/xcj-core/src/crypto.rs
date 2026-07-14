//! 通信加密模块(M2.4 实现)
//!
//! 详见 ADR 0020 (HTTPS + RSA + AES-256-GCM) / 0021 (HMAC 签名 + nonce + 时间戳)
//!
//! 流程:
//! 1. handshake: 客户端生成临时 AES-256 密钥,RSA 公钥加密后发给服务端
//! 2. 后续请求:AES-256-GCM 加密请求体 + HMAC-SHA256 签名(method+path+timestamp+nonce+bodyHash)
//! 3. nonce 防重放:5 分钟内不可重复
//! 4. timestamp 防重放:偏差 > 60s 拒绝

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// AES-256-GCM 加密
///
/// # 参数
/// - `key`: 32 字节 AES 密钥
/// - `plaintext`: 明文
///
/// # 返回
/// `iv(12B) | ciphertext | tag(16B)` 拼接的 Buffer
pub fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256Gcm::new(key.into());
    let mut iv_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "AES_ENCRYPT_FAILED")?;
    let mut result = Vec::with_capacity(12 + ciphertext.len() + 16);
    result.extend_from_slice(&iv_bytes);
    result.extend_from_slice(&ciphertext[..ciphertext.len() - 16]);
    result.extend_from_slice(&ciphertext[ciphertext.len() - 16..]);
    Ok(result)
}

/// AES-256-GCM 解密
pub fn aes_decrypt(key: &[u8; 32], combined: &[u8]) -> Result<Vec<u8>, &'static str> {
    if combined.len() < 12 + 16 {
        return Err("INVALID_COMBINED_LENGTH");
    }
    let iv = &combined[..12];
    let tag = &combined[combined.len() - 16..];
    let ciphertext = &combined[12..combined.len() - 16];
    let mut full = Vec::with_capacity(ciphertext.len() + tag.len());
    full.extend_from_slice(ciphertext);
    full.extend_from_slice(tag);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, full.as_ref())
        .map_err(|_| "AES_DECRYPT_FAILED")
}

/// HMAC-SHA256 签名
pub fn hmac_sign(key: &[u8], message: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key length error");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// HMAC-SHA256 常量时间验证
pub fn hmac_verify(key: &[u8], message: &str, signature: &str) -> bool {
    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(key) else {
        return false;
    };
    mac.update(message.as_bytes());
    let Ok(expected) = hex::decode(signature) else {
        return false;
    };
    mac.verify_slice(&expected).is_ok()
}

/// SHA-256 哈希(十六进制输出)
pub fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = [0xab; 32];
        let plaintext = b"hello xiaochengjian";
        let encrypted = aes_encrypt(&key, plaintext).unwrap();
        let decrypted = aes_decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_tamper_fails() {
        let key = [0xab; 32];
        let encrypted = aes_encrypt(&key, b"test").unwrap();
        let mut tampered = encrypted.clone();
        tampered[12] ^= 0xff;
        assert!(aes_decrypt(&key, &tampered).is_err());
    }

    #[test]
    fn test_hmac_sign_verify() {
        let key = b"secret-key";
        let sig = hmac_sign(key, "message");
        assert_eq!(sig.len(), 64);
        assert!(hmac_verify(key, "message", &sig));
        assert!(!hmac_verify(key, "tampered", &sig));
    }

    #[test]
    fn test_sha256() {
        let hash = sha256_hex("test");
        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }
}
