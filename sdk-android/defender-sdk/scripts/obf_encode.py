#!/usr/bin/env python3
"""
obf_encode.py - XOR 字符串混淆编码工具(ADR 0088 M7)

把敏感字符串(检测关键词等)用 XOR 0x5A 编码为 C 字节数组,
运行时由 obf_decode() 解码。静态分析(strings/IDA)看到编码字节,不可读。

用法:
    python3 obf_encode.py "frida" "gum-js-loop"

输出:
    static const unsigned char OBF_FRIDA[] = {0x3c, 0x28, 0x33, 0x3e, 0x3b};  /* "frida" */

key 必须与 anti_frida.c / sig_verify.c 中的 OBF_KEY (0x5A) 一致。
"""
import sys

OBF_KEY = 0x5A


def encode(s: str) -> str:
    return ", ".join(f"0x{ord(c) ^ OBF_KEY:02x}" for c in s)


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    for s in sys.argv[1:]:
        # 生成 C 标识符名:大写 + 下划线
        name = "OBF_" + s.upper().replace("-", "_").replace(":", "_")
        print(f'static const unsigned char {name}[] = {{{encode(s)}}};  /* "{s}" */')


if __name__ == "__main__":
    main()
