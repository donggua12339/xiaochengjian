#!/usr/bin/env python3
"""
build_inner_so.py - 编译 inner_defender.so + XOR 加密 + 生成 C 头文件

流程:
  1. 用 NDK 交叉编译 inner_defender.c → libinner_defender.so (arm64-v8a + armeabi-v7a)
  2. 读取 .so 二进制,用 16 字节 XOR 密钥加密
  3. 生成 inner_defender_enc.h(包含加密数据 C 数组)
  4. 外壳编译时 #include 该头文件,嵌入加密 .so 到 .rodata

用法:
  python scripts/build_inner_so.py [--ndk-path <path>] [--abi arm64-v8a]

注意:
  - 需要 Android NDK(默认从 ANDROID_HOME/ndk 或 ANDROID_NDK_HOME 查找)
  - 每次修改 inner_defender.c 后需重新运行
  - 生成的 .h 文件会被 git 跟踪(加密数据是构建产物的一部分)
"""
import os
import sys
import struct
import subprocess
import argparse
import glob

# XOR 密钥(与 inner_defender_enc.h 中的默认值一致)
XOR_KEY = bytes([0x5A, 0x3C, 0x7E, 0xA1, 0x4F, 0x8B, 0x2D, 0xE6,
                  0x91, 0x63, 0xC5, 0x07, 0xB8, 0x44, 0xF2, 0x19])

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CPP_DIR = os.path.join(SCRIPT_DIR, '..', 'src', 'main', 'cpp')
INNER_SRC = os.path.join(CPP_DIR, 'inner_defender.c')
OUTPUT_H = os.path.join(CPP_DIR, 'inner_defender_enc.h')


def find_ndk():
    """查找 NDK 路径"""
    # 环境变量
    ndk = os.environ.get('ANDROID_NDK_HOME') or os.environ.get('ANDROID_NDK_ROOT')
    if ndk and os.path.exists(ndk):
        return ndk

    # ANDROID_HOME/ndk/
    sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if sdk:
        ndk_dir = os.path.join(sdk, 'ndk')
        if os.path.exists(ndk_dir):
            versions = sorted(os.listdir(ndk_dir), reverse=True)
            if versions:
                return os.path.join(ndk_dir, versions[0])

    # 默认路径
    default = os.path.expanduser('~/AppData/Local/Android/Sdk/ndk')
    if os.path.exists(default):
        versions = sorted(os.listdir(default), reverse=True)
        if versions:
            return os.path.join(default, versions[0])

    return None


def find_clang(ndk_path, abi):
    """查找 NDK clang 编译器,返回 (clang_exe, target_triple)"""
    toolchain_dir = os.path.join(ndk_path, 'toolchains', 'llvm', 'prebuilt')
    host_dirs = glob.glob(os.path.join(toolchain_dir, '*'))
    if not host_dirs:
        raise RuntimeError(f"找不到 NDK toolchain: {toolchain_dir}")
    host_dir = host_dirs[0]
    bin_dir = os.path.join(host_dir, 'bin')

    # 使用 clang.exe + --target(避免 Windows shell 脚本问题)
    clang_exe = os.path.join(bin_dir, 'clang.exe')
    if not os.path.exists(clang_exe):
        clang_exe = os.path.join(bin_dir, 'clang')
    if not os.path.exists(clang_exe):
        raise RuntimeError(f"找不到 clang: {bin_dir}")

    targets = {
        'arm64-v8a': 'aarch64-linux-android24',
        'armeabi-v7a': 'armv7a-linux-androideabi24',
    }
    target = targets.get(abi)
    if not target:
        raise RuntimeError(f"不支持的 ABI: {abi}")

    return clang_exe, target


def compile_inner_so(ndk_path, abi, output_dir):
    """编译 inner_defender.c → libinner_defender.so"""
    clang_exe, target = find_clang(ndk_path, abi)
    output_so = os.path.join(output_dir, f'libinner_defender_{abi}.so')

    cmd = [
        clang_exe,
        f'--target={target}',
        '-shared', '-fPIC', '-O2',
        '-fvisibility=hidden',
        '-ffunction-sections', '-fdata-sections',
        '-fno-builtin',       # 防止编译器生成隐式 libc 调用
        '-nostdlib',          # 不链接 libc(自实现 Linker 无法初始化 libc)
        '-Wl,--gc-sections',
        '-Wl,--exclude-libs,ALL',
        '-Wl,-s',
        '-o', output_so,
        INNER_SRC,
    ]

    print(f"[{abi}] 编译: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[{abi}] 编译失败: {result.stderr}")
        sys.exit(1)

    size = os.path.getsize(output_so)
    print(f"[{abi}] 编译成功: {output_so} ({size} bytes)")
    return output_so


def xor_encrypt(data, key):
    """XOR 加密"""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def generate_header(so_path, abi):
    """生成 C 头文件"""
    with open(so_path, 'rb') as f:
        raw_data = f.read()

    encrypted = xor_encrypt(raw_data, XOR_KEY)

    # 验证:解密后应该是 ELF
    decrypted_check = xor_encrypt(encrypted, XOR_KEY)
    assert decrypted_check[:4] == b'\x7fELF', "加密验证失败"

    # 生成 C 数组
    lines = []
    lines.append('/**')
    lines.append(' * inner_defender_enc.h - 加密的 inner .so 数据(自动生成)')
    lines.append(f' * ABI: {abi}')
    lines.append(f' * 原始大小: {len(raw_data)} bytes')
    lines.append(f' * 加密大小: {len(encrypted)} bytes')
    lines.append(' * 由 build_inner_so.py 生成,请勿手动修改')
    lines.append(' */')
    lines.append('#ifndef INNER_DEFENDER_ENC_H')
    lines.append('#define INNER_DEFENDER_ENC_H')
    lines.append('')
    lines.append('#include <stdint.h>')
    lines.append('')

    # XOR 密钥
    key_hex = ', '.join(f'0x{b:02X}' for b in XOR_KEY)
    lines.append(f'static const uint8_t INNER_ENC_KEY[16] = {{ {key_hex} }};')
    lines.append('static const size_t INNER_ENC_KEY_LEN = 16;')
    lines.append('')

    # 加密数据(每行 16 字节)
    lines.append(f'static const uint8_t INNER_ENC_DATA[{len(encrypted)}] = {{')
    for i in range(0, len(encrypted), 16):
        chunk = encrypted[i:i+16]
        hex_str = ', '.join(f'0x{b:02X}' for b in chunk)
        comma = ',' if i + 16 < len(encrypted) else ''
        lines.append(f'    {hex_str}{comma}')
    lines.append('};')
    lines.append(f'static const int INNER_ENC_SIZE = {len(encrypted)};')
    lines.append('')
    lines.append('#endif /* INNER_DEFENDER_ENC_H */')

    header_content = '\n'.join(lines) + '\n'

    with open(OUTPUT_H, 'w') as f:
        f.write(header_content)

    print(f"头文件已生成: {OUTPUT_H} ({len(header_content)} bytes)")


def main():
    parser = argparse.ArgumentParser(description='编译 inner .so + 加密 + 生成头文件')
    parser.add_argument('--ndk-path', help='NDK 路径')
    parser.add_argument('--abi', default='arm64-v8a', choices=['arm64-v8a', 'armeabi-v7a'],
                        help='目标 ABI(默认 arm64-v8a)')
    args = parser.parse_args()

    ndk_path = args.ndk_path or find_ndk()
    if not ndk_path:
        print("错误: 找不到 Android NDK,请用 --ndk-path 指定")
        sys.exit(1)
    print(f"NDK: {ndk_path}")

    # 编译
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        so_path = compile_inner_so(ndk_path, args.abi, tmpdir)
        generate_header(so_path, args.abi)

    print(f"\n完成! inner .so 已加密嵌入 {OUTPUT_H}")
    print("下一步: 重新编译外壳 defender-sdk(会自动 #include 新头文件)")


if __name__ == '__main__':
    main()
