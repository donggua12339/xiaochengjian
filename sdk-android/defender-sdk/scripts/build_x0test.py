#!/usr/bin/env python3
"""
build_x0test.py - X0-3 原型构建:编译 x0test.c → libx0test.so(arm64),
RC4 加密(魔数框架)→ 生成 x0test_enc.h 供 stub(xcj_loader.c)嵌入。

复用 build_inner_so.py 的 NDK 探测(find_ndk/find_clang)+ so_cipher.py 的框架封装。

用法:
  python scripts/build_x0test.py [--ndk-path <path>] [--abi arm64-v8a]

原型用固定密钥 x0-prototype-key;生产由 Packer 每构建随机生成 + X1 OBF 混淆(见 ADR 0092 §4)。
"""
import os
import sys
import subprocess
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_inner_so import find_ndk, find_clang   # 复用 NDK 探测
import so_cipher

HERE = os.path.dirname(os.path.abspath(__file__))
CPP = os.path.join(HERE, "..", "src", "main", "cpp")
KEY = b"x0-prototype-key"   # 原型固定密钥


def build_payload_so(ndk: str, abi: str, out_dir: str) -> str:
    clang_exe, target = find_clang(ndk, abi)
    # NDK sysroot(jni.h / android/log.h 在此);clang 在 .../prebuilt/<host>/bin/
    sysroot = os.path.join(os.path.dirname(os.path.dirname(clang_exe)), "sysroot")
    src = os.path.join(CPP, "x0test.c")
    out = os.path.join(out_dir, "libx0test.so")
    cmd = [
        clang_exe, f"--target={target}", f"--sysroot={sysroot}",
        "-shared", "-fPIC", "-O2",
        "-I", CPP,
        src, "-o", out,
        "-llog",
    ]
    print("[build_x0test] 编译:", " ".join(os.path.basename(c) if os.path.sep in c else c for c in cmd))
    subprocess.run(cmd, check=True)
    return out


def gen_header(framed: bytes, key: bytes, out_path: str) -> None:
    def carray(data: bytes, per: int = 16) -> str:
        lines = []
        for i in range(0, len(data), per):
            chunk = data[i:i + per]
            lines.append("    " + ",".join(f"0x{b:02x}" for b in chunk) + ",")
        return "\n".join(lines)

    key_arr = ",".join(f"0x{b:02x}" for b in key)
    content = f"""/* x0test_enc.h - build_x0test.py 生成,勿手改。加密载荷 libx0test.so(RC4 + 魔数框架)。 */
#ifndef X0TEST_ENC_H
#define X0TEST_ENC_H
#include <stdint.h>
#define X0TEST_ENC_SIZE {len(framed)}
static const uint8_t X0TEST_ENC_DATA[X0TEST_ENC_SIZE] = {{
{carray(framed)}
}};
#define X0TEST_ENC_KEY_LEN {len(key)}
static const uint8_t X0TEST_ENC_KEY[X0TEST_ENC_KEY_LEN] = {{ {key_arr} }};
#endif
"""
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="X0-3 原型:编译+加密载荷,生成 x0test_enc.h")
    ap.add_argument("--abi", default="arm64-v8a")
    ap.add_argument("--ndk-path", help="NDK 路径(默认自动探测)")
    args = ap.parse_args()

    ndk = args.ndk_path or find_ndk()
    if not ndk:
        print("错误:找不到 Android NDK,请用 --ndk-path 指定")
        sys.exit(1)
    print(f"[build_x0test] NDK: {ndk}")

    with tempfile.TemporaryDirectory() as tmp:
        so = build_payload_so(ndk, args.abi, tmp)
        with open(so, "rb") as f:
            plain = f.read()
        print(f"[build_x0test] libx0test.so: {len(plain)} bytes")
        framed = so_cipher.frame(plain, KEY)   # [密文][MAGIC][len]
        out_h = os.path.join(CPP, "x0test_enc.h")
        gen_header(framed, KEY, out_h)
        print(f"[build_x0test] 生成 {out_h}(框架 {len(framed)} bytes)")


if __name__ == "__main__":
    main()
