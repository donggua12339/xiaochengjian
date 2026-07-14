//! 完整性校验模块(M2.6 实现)
//!
//! 详见 ADR 0025 (完整性校验)
//!
//! 校验项:
//!  - APK 签名校验(直接读 APK 文件解析签名,不依赖系统 API)
//!  - so 自校验(.text 段 hash 对比编译时嵌入值)
//!  - 服务端下发校验值(从服务端拉预期 hash 对比)

use sha2::{Digest, Sha256};

/// 计算 APK 签名 hash(简化版,实际需解析 APK ZIP 结构 + v2/v3 签名块)
///
/// # 参数
/// - `apk_path`: APK 文件路径
///
/// # 返回
/// 64 字符十六进制 SHA-256(实际应解析签名块,这里简化为整个文件 hash 用于测试)
pub fn compute_apk_signature_hash(apk_path: &str) -> Option<String> {
    let data = std::fs::read(apk_path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(hex::encode(hasher.finalize()))
}

/// 计算数据 SHA-256
pub fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// 校验 APK 签名是否在白名单内
///
/// # 参数
/// - `apk_path`: APK 文件路径
/// - `allow_list`: 允许的签名 hash 列表(开发者后台配置)
pub fn verify_apk_signature(apk_path: &str, allow_list: &[String]) -> bool {
    let Some(actual) = compute_apk_signature_hash(apk_path) else {
        return false;
    };
    allow_list.iter().any(|h| h.eq_ignore_ascii_case(&actual))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_value() {
        let hash = sha256(b"test");
        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_verify_apk_signature_empty_list() {
        // 空白名单总是拒绝
        assert!(!verify_apk_signature("nonexistent.apk", &[]));
    }
}
