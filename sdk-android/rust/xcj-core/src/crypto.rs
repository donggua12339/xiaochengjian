//! 通信加密模块
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
use rand::RngCore;
use rsa::{Oaep, RsaPublicKey};
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// RSA 公钥加密(用于 handshake 加密临时 AES 密钥)
///
/// 使用 RSA-OAEP + SHA-256(与后端 CryptoService.rsaDecrypt 对应)
///
/// # 参数
/// - `public_key_pem`: PEM 格式的 RSA 公钥
/// - `plaintext`: 待加密数据(通常是 32 字节 AES 密钥)
pub fn rsa_encrypt(public_key_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|_| "INVALID_PUBLIC_KEY")?;
    let padding = Oaep::new::<Sha256>();
    public_key
        .encrypt(&mut rand::thread_rng(), padding, plaintext)
        .map_err(|_| "RSA_ENCRYPT_FAILED")
}

/// 生成 32 字节随机 AES 密钥(用于 handshake 临时密钥)
pub fn generate_aes_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// 生成随机 nonce(16 字节十六进制,用于请求签名防重放)
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

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

    #[test]
    fn test_rsa_encrypt_with_generated_key() {
        use rsa::pkcs8::EncodePublicKey;
        // 生成 RSA 密钥对(测试用,2048 位)
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        let plaintext = b"test-aes-key-32-bytes-1234567890ab";
        let encrypted = rsa_encrypt(&public_key_pem, plaintext).unwrap();
        // 密文长度应等于 256 字节(2048 位 RSA)
        assert_eq!(encrypted.len(), 256);

        // 用私钥解密,应还原原文
        let padding = Oaep::new::<Sha256>();
        let decrypted = private_key.decrypt(padding, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rsa_encrypt_invalid_pem() {
        let result = rsa_encrypt("not-a-valid-pem", b"data");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "INVALID_PUBLIC_KEY");
    }

    #[test]
    fn test_generate_aes_key_is_32_bytes() {
        let key = generate_aes_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_generate_aes_key_is_random() {
        let key1 = generate_aes_key();
        let key2 = generate_aes_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_generate_nonce_format() {
        let nonce = generate_nonce();
        // 16 字节十六进制 = 32 字符
        assert_eq!(nonce.len(), 32);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_nonce_is_random() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_aes_decrypt_invalid_length() {
        let key = [0xab; 32];
        // 少于 12 + 16 = 28 字节
        let result = aes_decrypt(&key, b"too-short");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "INVALID_COMBINED_LENGTH");
    }

    #[test]
    fn test_aes_encrypt_produces_correct_layout() {
        let key = [0xab; 32];
        let plaintext = b"hello";
        let encrypted = aes_encrypt(&key, plaintext).unwrap();
        // iv(12) + ciphertext(plaintext.len()) + tag(16)
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);
    }

    #[test]
    fn test_hmac_verify_invalid_signature_format() {
        let key = b"secret";
        // 非十六进制签名应返回 false
        assert!(!hmac_verify(key, "msg", "not-hex!"));
    }

    #[test]
    fn test_hmac_verify_wrong_key() {
        let key = b"secret";
        let sig = hmac_sign(key, "message");
        assert!(!hmac_verify(b"wrong-key", "message", &sig));
    }

    #[test]
    fn test_sha256_empty_string() {
        let hash = sha256_hex("");
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_long_input() {
        let input = "a".repeat(1000);
        let hash = sha256_hex(&input);
        assert_eq!(hash.len(), 64);
    }
}
