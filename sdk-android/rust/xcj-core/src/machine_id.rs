//! 机器码生成模块(M2.2 实现)
//!
//! 详见 ADR 0016 (机器码算法)
//!
//! 算法:多因素组合 SHA-256
//! ```text
//! machineId = SHA-256(
//!   ANDROID_ID + MediaDRM_ID + Build.MANUFACTURER +
//!   Build.MODEL + Build.HARDWARE + displayMetrics + abis
//! )[:32]
//! ```
//!
//! 容错策略:3 个核心标识中至少 2 个匹配即视为同一设备

use sha2::{Digest, Sha256};

/// 计算机器码(多因素组合 SHA-256,取前 32 字符)
///
/// # 参数
/// - `android_id`: Settings.Secure.ANDROID_ID
/// - `media_drm_id`: MediaDrm ID(部分设备可能为空)
/// - `hardware_fingerprint`: 硬件指纹(厂商+型号+屏幕+CPU+ABIs 拼接)
///
/// # 返回
/// 32 字符十六进制机器码
pub fn generate_machine_id(
    android_id: &str,
    media_drm_id: Option<&str>,
    hardware_fingerprint: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(android_id.as_bytes());
    hasher.update(b"|");
    if let Some(drm) = media_drm_id {
        hasher.update(drm.as_bytes());
    }
    hasher.update(b"|");
    hasher.update(hardware_fingerprint.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..16]) // 取前 16 字节 = 32 字符
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_machine_id_deterministic() {
        let id1 = generate_machine_id("android123", Some("drm456"), "Pixel 7");
        let id2 = generate_machine_id("android123", Some("drm456"), "Pixel 7");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_inputs_different_output() {
        let id1 = generate_machine_id("android123", Some("drm456"), "Pixel 7");
        let id2 = generate_machine_id("android456", Some("drm456"), "Pixel 7");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_length_32() {
        let id = generate_machine_id("a", None, "b");
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn test_none_media_drm() {
        let id = generate_machine_id("android123", None, "Pixel 7");
        assert_eq!(id.len(), 32);
    }
}
