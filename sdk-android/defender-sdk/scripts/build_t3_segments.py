#!/usr/bin/env python3
"""
build_t3_segments.py - T3 字符串分段散列构建工具(天衍)

将敏感字符串拆 2-4 段,XOR 加密后散列存储,生成 C 头文件。
运行时由 t3_segment_str.c 的 t3_assemble() 重组+解密。

用法:
    python scripts/build_t3_segments.py strings.txt --output t3_segments.h --key-hex <hex>

strings.txt 格式:每行一个待保护字符串(UTF-8)。
也可 --builtin 模式:自动从源码提取检测关键词。

产出 t3_segments.h:
    - T3_SEG_POOL[]: 所有加密片段连续存储
    - T3_DESCRIPTORS[]: 每个字符串的分段描述符
    - T3_DESCRIPTOR_COUNT / T3_SEG_POOL_SIZE
"""
import argparse
import os
import random
import struct
import sys


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def split_string(s: str, rng: random.Random) -> list:
    """将字符串拆为 2-4 段(随机)"""
    raw = s.encode('utf-8')
    n = len(raw)
    if n <= 2:
        return [raw]
    # 随机分段数 2-4(不超过字符串长度)
    seg_count = min(rng.randint(2, 4), n)
    # 随机切分点
    cuts = sorted(rng.sample(range(1, n), seg_count - 1))
    segments = []
    prev = 0
    for c in cuts:
        segments.append(raw[prev:c])
        prev = c
    segments.append(raw[prev:])
    return segments


def generate_header(strings: list, key: bytes, seed: int = 42) -> str:
    """生成 t3_segments.h"""
    rng = random.Random(seed)

    seg_pool = bytearray()
    descriptors = []

    for s in strings:
        segments = split_string(s, rng)
        seg_count = len(segments)
        seg_offsets = []
        seg_lengths = []

        for seg in segments:
            encrypted = xor_encrypt(seg, key)
            offset = len(seg_pool)
            seg_pool.extend(encrypted)
            seg_offsets.append(offset)
            seg_lengths.append(len(encrypted))

        # 补齐到 T3_MAX_SEGMENTS=4
        while len(seg_offsets) < 4:
            seg_offsets.append(0)
            seg_lengths.append(0)

        descriptors.append((seg_count, seg_offsets, seg_lengths))

    # 生成 C 头文件
    lines = []
    lines.append('/**')
    lines.append(' * t3_segments.h - T3 分段散列字符串(自动生成,请勿手动修改)')
    lines.append(f' * 由 build_t3_segments.py 生成 | {len(strings)} 个字符串 | 池大小 {len(seg_pool)} bytes')
    lines.append(' */')
    lines.append('#ifndef T3_SEGMENTS_H')
    lines.append('#define T3_SEGMENTS_H')
    lines.append('')
    lines.append('#include <stdint.h>')
    lines.append('#include "t3_segment_str.c"  /* t3_descriptor_t 定义 */')
    lines.append('')

    # 段池
    lines.append(f'static const uint8_t T3_SEG_POOL_DATA[{len(seg_pool)}] = {{')
    for i in range(0, len(seg_pool), 16):
        chunk = seg_pool[i:i+16]
        hex_str = ', '.join(f'0x{b:02X}' for b in chunk)
        comma = ',' if i + 16 < len(seg_pool) else ''
        lines.append(f'    {hex_str}{comma}')
    lines.append('};')
    lines.append(f'const uint8_t *T3_SEG_POOL = T3_SEG_POOL_DATA;')
    lines.append(f'const uint32_t T3_SEG_POOL_SIZE = {len(seg_pool)};')
    lines.append('')

    # 描述符
    lines.append(f'static const t3_descriptor_t T3_DESC_DATA[{len(descriptors)}] = {{')
    for seg_count, offsets, lengths in descriptors:
        off_str = ', '.join(str(o) for o in offsets)
        len_str = ', '.join(str(l) for l in lengths)
        lines.append(f'    {{{seg_count}, {{{off_str}}}, {{{len_str}}}}},')
    lines.append('};')
    lines.append(f'const t3_descriptor_t *T3_DESCRIPTORS = T3_DESC_DATA;')
    lines.append(f'const uint32_t T3_DESCRIPTOR_COUNT = {len(descriptors)};')
    lines.append('')
    lines.append('#endif /* T3_SEGMENTS_H */')

    return '\n'.join(lines) + '\n'


# 内置敏感关键词(自动提取模式)
BUILTIN_STRINGS = [
    "/proc/self/maps",
    "/proc/self/status",
    "/proc/self/mem",
    "/proc/net/tcp",
    "frida-agent",
    "frida:rpc",
    "LIBFRIDA",
    "liblsplant",
    "cache/decrypt",
    "bin.mt",
    ".mt.plus",
    "com.liaoin",
    "XposedBridge",
    "de.robv.android.xposed",
    "/data/adb/modules",
    "/system/bin/su",
    "/sbin/magisk",
    "KernelSU",
    "SRPatch",
    "LSPatch",
    "gum-js-loop",
    "gmain",
    "TracerPid",
    "ptrace_stop",
]


def main():
    parser = argparse.ArgumentParser(description='T3 字符串分段散列构建工具')
    parser.add_argument('input', nargs='?', help='输入字符串文件(每行一个)')
    parser.add_argument('--builtin', action='store_true', help='使用内置敏感关键词列表')
    parser.add_argument('--output', '-o', default='t3_segments.h', help='输出头文件路径')
    parser.add_argument('--key-hex', help='XOR 密钥(hex,默认随机)')
    parser.add_argument('--seed', type=int, default=42, help='分段随机种子')
    args = parser.parse_args()

    if args.builtin:
        strings = BUILTIN_STRINGS
    elif args.input:
        with open(args.input, 'r', encoding='utf-8') as f:
            strings = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        parser.error('需要 --builtin 或输入文件')
        return

    if args.key_hex:
        key = bytes.fromhex(args.key_hex)
    else:
        key = os.urandom(16)
        print(f"随机密钥(hex): {key.hex()}")

    print(f"=== T3 分段散列: {len(strings)} 个字符串 ===")

    header = generate_header(strings, key, args.seed)
    output_path = args.output
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(header)

    print(f"输出: {output_path}")
    print(f"段池大小: 见头文件 T3_SEG_POOL_SIZE")
    print("完成!")


if __name__ == '__main__':
    main()
