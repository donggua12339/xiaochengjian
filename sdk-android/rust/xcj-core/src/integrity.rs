//! 完整性校验模块
//!
//! 详见 ADR 0025 (完整性校验) / 0062 (签名白名单下发)
//!
//! 校验项:
//!  - APK 签名 hash 比对(服务端下发白名单,客户端拉取比对)
//!
//! 注:v2 已撤掉 so 自校验(.text 段 hash 嵌入)设施
//! 理由:服务端验证是权威,客户端自校验 ROI 低 + 阻碍合法审计

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

    #[test]
    fn test_compute_apk_signature_nonexistent_file() {
        // 不存在的文件返回 None
        assert!(compute_apk_signature_hash("nonexistent.apk").is_none());
    }

    #[test]
    fn test_verify_apk_signature_nonexistent_file() {
        // 文件不存在 + 非空白名单 -> false
        assert!(!verify_apk_signature("nonexistent.apk", &["hash1".to_string()]));
    }

    #[test]
    fn test_sha256_known_value_test() {
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let hash = sha256(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_empty() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_case_insensitive_compare() {
        // verify_apk_signature 用 eq_ignore_ascii_case,大小写不敏感
        // 先计算一个真实文件的 hash,然后大小写变换对比
        use std::io::Write;
        let tmp = std::env::temp_dir().join("xcj_integrity_test.apk");
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(b"fake apk content").unwrap();
        drop(f);

        let actual = compute_apk_signature_hash(tmp.to_str().unwrap()).unwrap();
        // 白名单用大写
        let allow_upper: Vec<String> = vec![actual.to_uppercase()];
        assert!(verify_apk_signature(tmp.to_str().unwrap(), &allow_upper));

        // 白名单用小写
        let allow_lower: Vec<String> = vec![actual.to_lowercase()];
        assert!(verify_apk_signature(tmp.to_str().unwrap(), &allow_lower));

        // 白名单不包含实际 hash
        let allow_wrong: Vec<String> = vec!["wronghash".to_string()];
        assert!(!verify_apk_signature(tmp.to_str().unwrap(), &allow_wrong));

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_verify_apk_signature_multiple_hashes_in_list() {
        // 白名单有多个 hash,任一匹配即通过
        use std::io::Write;
        let tmp = std::env::temp_dir().join("xcj_integrity_multi.apk");
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(b"content").unwrap();
        drop(f);

        let actual = compute_apk_signature_hash(tmp.to_str().unwrap()).unwrap();
        let allow: Vec<String> = vec![
            "wrong1".to_string(),
            actual.clone(),
            "wrong2".to_string(),
        ];
        assert!(verify_apk_signature(tmp.to_str().unwrap(), &allow));

        std::fs::remove_file(&tmp).ok();
    }
}
