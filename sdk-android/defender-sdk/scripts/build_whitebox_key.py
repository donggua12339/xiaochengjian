#!/usr/bin/env python3
"""
build_whitebox_key.py - 白盒密钥生成工具(天衍远期)

将 XOR 密钥熔入 S-box 查找表,使 .rodata 中不存在连续密钥字节。
攻击者看到的是一组 256-entry 置换表,无法直接提取密钥。

原理:
  原始: plain[i] = enc[i] ^ key[i % key_len]
  白盒: plain[i] = SBOX[i % key_len][enc[i]]
  其中 SBOX[j][x] = x ^ key[j] (对每个 key byte 位置 j 生成一个 256B 查找表)

对抗效果:
  - 静态分析: .rodata 中只有 N 个 256B 置换表,无"密钥"模式
  - IDA F5: 看到的是 table[enc[i]],不是 xor 指令
  - 差分分析: 需要 256 次选择明文才能还原一个 key byte(vs 1 次 XOR 已知明文)

用法:
    python scripts/build_whitebox_key.py --key-hex <hex> --output wb_sbox.h

产出 wb_sbox.h:
    - WB_SBOX[N][256]: N 个查找表(N = key_len)
    - WB_KEY_LEN: 表数量
"""
import argparse
import os
import sys


def generate_sboxes(key: bytes) -> list:
    """为每个 key byte 生成一个 256-entry S-box"""
    sboxes = []
    for kb in key:
        sbox = [(x ^ kb) & 0xFF for x in range(256)]
        sboxes.append(sbox)
    return sboxes


def generate_header(key: bytes) -> str:
    """生成 wb_sbox.h"""
    sboxes = generate_sboxes(key)
    n = len(sboxes)

    lines = []
    lines.append('/**')
    lines.append(' * wb_sbox.h - 白盒密钥查找表(自动生成,请勿手动修改)')
    lines.append(f' * 由 build_whitebox_key.py 生成 | {n} 个 S-box | 原始密钥不可提取')
    lines.append(' *')
    lines.append(' * 用法: plain[i] = WB_SBOX[i % WB_KEY_LEN][enc[i]]')
    lines.append(' */')
    lines.append('#ifndef WB_SBOX_H')
    lines.append('#define WB_SBOX_H')
    lines.append('')
    lines.append('#include <stdint.h>')
    lines.append('')
    lines.append(f'#define WB_KEY_LEN {n}')
    lines.append('')
    lines.append(f'static const uint8_t WB_SBOX[WB_KEY_LEN][256] = {{')

    for j, sbox in enumerate(sboxes):
        hex_vals = ', '.join(f'0x{v:02X}' for v in sbox)
        comma = ',' if j < n - 1 else ''
        # 每行 16 个值,格式化输出
        lines.append(f'    /* S-box {j} */')
        lines.append('    {')
        for i in range(0, 256, 16):
            chunk = sbox[i:i+16]
            hex_str = ', '.join(f'0x{v:02X}' for v in chunk)
            trail = ',' if i + 16 < 256 else ''
            lines.append(f'        {hex_str}{trail}')
        lines.append(f'    }}{comma}')

    lines.append('};')
    lines.append('')
    lines.append('#endif /* WB_SBOX_H */')

    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='白盒密钥 S-box 生成')
    parser.add_argument('--key-hex', help='XOR 密钥(hex)')
    parser.add_argument('--random', action='store_true', help='生成随机 16 字节密钥')
    parser.add_argument('--output', '-o', default='wb_sbox.h', help='输出头文件')
    args = parser.parse_args()

    if args.random:
        key = os.urandom(16)
        print(f"随机密钥(hex): {key.hex()}")
    elif args.key_hex:
        key = bytes.fromhex(args.key_hex)
    else:
        parser.error('需要 --key-hex 或 --random')
        return

    print(f"=== 白盒密钥生成: {len(key)} 字节 → {len(key)} 个 S-box ===")

    header = generate_header(key)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(header)

    print(f"输出: {args.output}")
    print(f"S-box 总大小: {len(key) * 256} bytes(分散在 .rodata,无连续密钥模式)")
    print("完成!")


if __name__ == '__main__':
    main()
