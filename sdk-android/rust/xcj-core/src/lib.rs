//! 小城笺 Android SDK Rust 核心
//!
//! 详见 ADR 0009 (Kotlin + Rust JNI) / 0023 (Rust 核心设计) / 0019 (安全哲学)
//!
//! 模块结构:
//!  - `jni_bridge`: JNI 入口(语义化命名 init/activate/validate 等)
//!  - `machine_id`: 机器码生成(多因素组合 SHA-256)
//!  - `card_key`: 卡密格式校验(4x4 + Luhn mod32)
//!  - `crypto`: RSA + AES-256-GCM + HMAC-SHA256
//!  - `integrity`: APK 签名白名单比对(服务端下发)
//!  - `cache`: 离线缓存加密
//!
//! 安全设计(ADR 0023):
//!  - 客户端只持有短期 token,不持有长期凭证
//!  - 离线缓存加密,密钥由服务端下发
//!  - 设备绑定服务端强制
//!  - 完整性校验靠服务端下发白名单(ADR 0062)
//!
//! 可选反逆向 features(默认关,开发者按需启用):
//!  - `obfstr`: 字符串混淆(编译时加密 URL/密钥/错误码)
//!  - `opaque-jni`: JNI 函数名非语义化(native01-08)
//!
//! 注:so 自校验 / 反调试 / 控制流平坦化 已在 v2 撤掉(grill 决策)
//! 理由:服务端验证是权威,客户端反逆向设施阻碍合法审计,ROI 低

#![deny(warnings)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod cache;
pub mod card_key;
pub mod crypto;
pub mod integrity;
pub mod jni_bridge;
pub mod machine_id;

/// SDK 版本
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }
}
