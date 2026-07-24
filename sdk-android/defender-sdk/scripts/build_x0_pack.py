#!/usr/bin/env python3
"""
build_x0_pack.py - X0-2:外壳 libxcj_defender.so 加密 + 嵌入(两段式,避开密钥鸡生蛋)

  用法 1(SDK 构建前):python scripts/build_x0_pack.py --genkey-header
      生成随机密钥 → x0_key.h(注入 stub)。密钥固定,与外壳字节无关,故无需两段构建。
  用法 2(SDK 构建后):python scripts/build_x0_pack.py --so <libxcj_defender.so>
      读 x0_key.h 的密钥,RC4 加密外壳 → xcj_payload.bin(嵌入 demo assets,noCompress)。
      若密文撞 zip/XCJSO1 魔数会告警(ELF 验真兜底,概率约 0.01%)。

生产:密钥由 Packer 每构建随机 + X1 OBF 混淆注入 stub;嵌入用 post-build zip 注入(任意 APK)。
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import so_cipher

HERE = os.path.dirname(os.path.abspath(__file__))
CPP = os.path.join(HERE, "..", "src", "main", "cpp")
KEY_HEADER = os.path.join(CPP, "x0_key.h")
DEMO_ASSETS = os.path.join(HERE, "..", "..", "defender-demo", "src", "main", "assets")


def gen_key_header(n: int = 32) -> bytes:
    key = so_cipher.gen_key(n)
    key_arr = ",".join(f"0x{b:02x}" for b in key)
    content = f"""/* x0_key.h - build_x0_pack.py 生成,勿手改。X0 外壳解密密钥(注入 stub)。 */
#ifndef X0_KEY_H
#define X0_KEY_H
#include <stdint.h>
#define X0_KEY_LEN {len(key)}
static const uint8_t X0_KEY[X0_KEY_LEN] = {{ {key_arr} }};
#endif
"""
    with open(KEY_HEADER, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    return key


def read_key_header() -> bytes:
    """从 x0_key.h 解析出密钥字节。"""
    with open(KEY_HEADER, "r", encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"X0_KEY\[X0_KEY_LEN\]\s*=\s*\{([^}]*)\}", text)
    if not m:
        raise RuntimeError("x0_key.h 中未找到 X0_KEY 数组")
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))


def main():
    import argparse
    ap = argparse.ArgumentParser(description="X0-2 外壳加密 + 嵌入")
    ap.add_argument("--genkey-header", action="store_true", help="生成随机密钥 → x0_key.h(SDK 构建前)")
    ap.add_argument("--key-bytes", type=int, default=32, help="--genkey-header 的密钥字节数")
    ap.add_argument("--so", help="已构建的 libxcj_defender.so 路径(SDK 构建后)")
    args = ap.parse_args()

    if args.genkey_header:
        key = gen_key_header(args.key_bytes)
        print(f"[build_x0_pack] 生成 x0_key.h,密钥(hex): {key.hex()}")
        return

    if args.so:
        key = read_key_header()
        with open(args.so, "rb") as f:
            plain = f.read()
        print(f"[build_x0_pack] 外壳 .so: {len(plain)} bytes;密钥(hex): {key.hex()}")
        framed = so_cipher.frame(plain, key)   # 用 x0_key.h 的固定密钥(与 stub 一致)
        cipher = framed[:-so_cipher.TRAILER_LEN]
        if so_cipher.contains_forbidden(cipher):
            print("[build_x0_pack] 警告:密文含 zip/XCJSO1 魔数(ELF 验真可兜底);如需干净请重新 --genkey-header 并重建")
        os.makedirs(DEMO_ASSETS, exist_ok=True)
        out = os.path.join(DEMO_ASSETS, "xcj_payload.bin")
        with open(out, "wb") as f:
            f.write(framed)
        print(f"[build_x0_pack] 密文载荷 -> {out}({len(framed)} bytes)")
        return

    ap.print_help()


if __name__ == "__main__":
    main()
