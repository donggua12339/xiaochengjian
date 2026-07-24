#!/usr/bin/env python3
"""
build_x0test.py - X0-3 原型构建:
  1. NDK 编译 x0test.c → libx0test.so(arm64)
  2. frame_clean 加密(自动避开 zip/框架魔数,撞了换随机密钥)
  3. 生成 x0_key.h(密钥,供 stub 编译)+ x0_payload.bin(密文框架,供嵌入 APK)

载荷密文作为 demo 的 noCompress asset(STORED)进 APK,stub 扫 APK 魔数定位。
原型跑通后,载荷换成真 libxcj_defender.so(见 ADR 0092 / build_x0_pack 流程)。

用法:python scripts/build_x0test.py [--ndk-path <path>] [--abi arm64-v8a]
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
DEMO_ASSETS = os.path.join(HERE, "..", "..", "defender-demo", "src", "main", "assets")
PROTO_KEY = b"x0-prototype-key"   # 首选密钥;撞魔数则 frame_clean 自动换随机密钥


def build_payload_so(ndk: str, abi: str, out_dir: str) -> str:
    clang_exe, target = find_clang(ndk, abi)
    sysroot = os.path.join(os.path.dirname(os.path.dirname(clang_exe)), "sysroot")
    src = os.path.join(CPP, "x0test.c")
    out = os.path.join(out_dir, "libx0test.so")
    cmd = [clang_exe, f"--target={target}", f"--sysroot={sysroot}",
           "-shared", "-fPIC", "-O2", "-I", CPP, src, "-o", out, "-llog"]
    subprocess.run(cmd, check=True)
    return out


def gen_key_header(key: bytes, out_path: str) -> None:
    key_arr = ",".join(f"0x{b:02x}" for b in key)
    content = f"""/* x0_key.h - build_x0test.py 生成,勿手改。X0 载荷解密密钥(注入 stub)。 */
#ifndef X0_KEY_H
#define X0_KEY_H
#include <stdint.h>
#define X0_KEY_LEN {len(key)}
static const uint8_t X0_KEY[X0_KEY_LEN] = {{ {key_arr} }};
#endif
"""
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="X0-3 原型:编译+加密载荷,生成 x0_key.h + x0_payload.bin")
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

        framed, key_used = so_cipher.frame_clean(plain, PROTO_KEY)

        # 密钥头(供 stub 编译)
        gen_key_header(key_used, os.path.join(CPP, "x0_key.h"))
        # 密文框架(供嵌入 APK,demo noCompress asset)
        os.makedirs(DEMO_ASSETS, exist_ok=True)
        payload_bin = os.path.join(DEMO_ASSETS, "xcj_payload.bin")
        with open(payload_bin, "wb") as f:
            f.write(framed)

        print(f"[build_x0test] x0_key.h 密钥(hex): {key_used.hex()}")
        print(f"[build_x0test] 密文载荷 -> {payload_bin}({len(framed)} bytes)")


if __name__ == "__main__":
    main()
