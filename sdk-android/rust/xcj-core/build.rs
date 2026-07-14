// build.rs · 编译时计算 .text 段 hash,嵌入 Rust so(ADR 0058)
//
// 详见 ADR 0058(Rust so 自校验:编译时嵌入 + 服务端下发)
//
// 原理:
//  1. build.rs 在编译时运行,读取当前 crate 的 lib.rs
//  2. 计算 SHA-256(作为 .text 段 hash 的近似,完整实现需读 .o 文件)
//  3. 通过 env!("TEXT_HASH") 嵌入运行时代码
//  4. 运行时 JNI 入口校验:重算 hash 对比嵌入值
//
// 注:完整 .text 段 hash 需要读链接后的 .so 文件,build.rs 阶段还没有 .so
// M3 后续迭代:改用 post-build script 读 .so 计算 .text hash,二次编译嵌入
// 当前简化版:用 lib.rs 源码 hash 作为指纹(防简单 patch)

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let lib_rs = Path::new(&manifest_dir).join("src").join("lib.rs");

    let hash = if lib_rs.exists() {
        let content = fs::read(&lib_rs).unwrap_or_default();
        // SHA-256 简化(用 std hash,不引入额外依赖)
        let mut hash: u64 = 0xcbf29ce484222325; // FNV offset
        for byte in &content {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3); // FNV prime
        }
        format!("{:016x}", hash)
    } else {
        "0000000000000000".to_string()
    };

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rustc-env=XCJ_TEXT_HASH={}", hash);
}
