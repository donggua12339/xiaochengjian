#!/usr/bin/env python3
"""
so_cipher.py - 玄甲 X0 外壳 SO 加密(构建期 RC4 加密 + 框架封装)

详见 docs/PRODUCT_XUANJIA_TIANYAN.md §X0 + ADR 0091 §3.1。
与 so_cipher.h 的 so_cipher_extract 严格互逆(C 端解密 = 本端加密的逆)。

框架布局(尾部固定 trailer,免扫描、O(1) 反向定位):
  [原始资源字节][RC4 密文(与明文等长)][MAGIC "XCJSO1"(6B)][明文长度 u32 LE(4B)]

功能:
  1. rc4_crypt(key, data) -> data                 RC4 流密码(加解密同函数)
  2. frame(plain, key) -> bytes                   RC4 加密 + 追加 [MAGIC][len]
  3. append_to_resource(res, plain, key) -> bytes  把框架追加到资源尾部(如 webp)
  4. extract(blob, key) -> plain                  与 C so_cipher_extract 同义(供自测)
  5. CLI --encrypt:供 Packer 集成(X0 后续阶段)
  6. __main__ 默认自测

密钥:默认开发密钥;生产由 Packer 每构建随机生成、注入外壳 loader(X1 OBF 混淆),
不在开源仓库。RC4 强度非目标(抗静态提取即可),强防护靠五层反动态 + memfd。
"""
import os
import struct
import sys

MAGIC = b"XCJSO1"
MAGIC_LEN = 6
TRAILER_LEN = MAGIC_LEN + 4


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """RC4 流密码;加解密同函数。key 非空。"""
    assert len(key) > 0, "RC4 key 不能为空"
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        ks = S[(S[i] + S[j]) & 0xff]
        out.append(b ^ ks)
    return bytes(out)


def frame(plain: bytes, key: bytes) -> bytes:
    """RC4 加密 + 框架 [密文][MAGIC][len u32 LE]。"""
    cipher = rc4_crypt(key, plain)
    return cipher + MAGIC + struct.pack("<I", len(plain))


def append_to_resource(res_bytes: bytes, plain: bytes, key: bytes) -> bytes:
    """把加密框架追加到资源(如 ic_launcher.webp)尾部;原资源字节不变。"""
    return res_bytes + frame(plain, key)


def extract(blob: bytes, key: bytes) -> bytes:
    """与 C so_cipher_extract 同义:尾部定位 [MAGIC][len] → RC4 解密。"""
    if len(blob) < TRAILER_LEN:
        raise ValueError("blob 过小")
    tail = blob[-TRAILER_LEN:]
    if tail[:MAGIC_LEN] != MAGIC:
        raise ValueError("魔数不匹配")
    (length,) = struct.unpack("<I", tail[MAGIC_LEN:])
    if length + TRAILER_LEN > len(blob):
        raise ValueError("长度越界")
    cipher = blob[-TRAILER_LEN - length:-TRAILER_LEN]
    return rc4_crypt(key, cipher)


def _self_test() -> None:
    keys = [b"xcj-dev-key", b"\x00\x01\x02", os.urandom(16), b"k" * 32]
    plains = [b"", b"\x7fELF" + os.urandom(4096), b"A" * 100000, bytes(range(256)) * 4]
    for key in keys:
        for p in plains:
            blob = frame(p, key)
            assert extract(blob, key) == p, (len(key), len(p))
            # 藏资源尾部后仍可提取,且原资源完好
            res = b"RIFF\x00\x00WEBP" + os.urandom(1234)   # 伪 webp 前缀
            blob2 = append_to_resource(res, p, key)
            assert extract(blob2, key) == p
            assert blob2[:len(res)] == res
    # 错误密钥 → 解出不同
    p = b"secret-so-bytes"
    assert extract(frame(p, b"key1"), b"key2") != p
    # 坏魔数 → 抛异常
    try:
        extract(b"garbage-no-magic-here!!", b"k")
        raise AssertionError("应抛魔数不匹配")
    except ValueError:
        pass
    print(f"[so_cipher] py 自洽通过:{len(keys)} key × {len(plains)} plain 全往返;"
          f"藏资源尾部可提取且原资源完好;错钥/坏魔数正确拦截")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="玄甲 X0 外壳 SO 加密(构建期)")
    ap.add_argument("--encrypt", nargs=2, metavar=("PLAIN_SO", "OUT_BIN"),
                    help="RC4 加密 PLAIN_SO,输出框架密文 [密文][MAGIC][len]")
    ap.add_argument("--prepend-resource", metavar="RES",
                    help="把密文框架追加到资源 RES 尾部(如 ic_launcher.webp);与 --encrypt 合用")
    ap.add_argument("--key", default="xcj-dev-key",
                    help="RC4 密钥(默认开发密钥;生产由 Packer 每构建随机注入)")
    args = ap.parse_args()
    key = args.key.encode()

    if args.encrypt:
        plain_so, out_bin = args.encrypt
        with open(plain_so, "rb") as f:
            plain = f.read()
        if args.prepend_resource:
            with open(args.prepend_resource, "rb") as f:
                res = f.read()
            blob = append_to_resource(res, plain, key)
            where = f" [藏于 {args.prepend_resource} 尾部]"
        else:
            blob = frame(plain, key)
            where = ""
        with open(out_bin, "wb") as f:
            f.write(blob)
        print(f"[so_cipher] 加密 {plain_so}({len(plain)}B) -> {out_bin}({len(blob)}B){where}")
        return

    _self_test()


if __name__ == "__main__":
    main()
