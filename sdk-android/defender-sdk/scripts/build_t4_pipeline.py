#!/usr/bin/env python3
"""
build_t4_pipeline.py - T4 完整构建流水线(解决鸡生蛋问题)

正确顺序:
  1. 生成/复用 T4 XOR 密钥 → t4_str_key.h
  2. 构建 defender-sdk(T4_ENABLED=ON,含 t4_str_key.h)
  3. 构建 demo APK(含 T4-enabled defender)
  4. encrypt-strings 修改 DEX(const-string → DexStringDecryptor.get)
  5. patch_x0 在加密后的 APK 上计算 hash(方案 A 匹配最终态)
  6. 输出: 可安装的 T4 加固 APK

用法:
    python scripts/build_t4_pipeline.py [--key-hex <hex>] [--skip-build]

前提:
    - Gradle/NDK/Python 环境就绪
    - injector 已 installDist(build/install/xcj-injector/lib/xcj-injector-all.jar)
"""
import argparse
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(SCRIPT_DIR)  # defender-sdk/
ANDROID_DIR = os.path.dirname(SDK_DIR)  # sdk-android/
DEMO_DIR = os.path.join(ANDROID_DIR, 'defender-demo')
INJECTOR_JAR = os.path.join(os.path.dirname(ANDROID_DIR), 'injector',
                            'build', 'install', 'xcj-injector', 'lib', 'xcj-injector-all.jar')
CPP_DIR = os.path.join(SDK_DIR, 'src', 'main', 'cpp')
T4_KEY_HEADER = os.path.join(CPP_DIR, 't4_str_key.h')


def run(cmd, cwd=None):
    print(f"  $ {cmd}")
    r = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  STDERR: {r.stderr[-500:]}")
        sys.exit(1)
    return r.stdout


def main():
    parser = argparse.ArgumentParser(description='T4 完整构建流水线')
    parser.add_argument('--key-hex', help='T4 XOR 密钥(hex,默认随机生成)')
    parser.add_argument('--skip-build', action='store_true', help='跳过 Gradle 构建(仅跑 encrypt+patch)')
    args = parser.parse_args()

    print("=== T4 完整构建流水线 ===")

    # Step 1: 生成/复用密钥
    if args.key_hex:
        key_hex = args.key_hex
    elif os.path.exists(T4_KEY_HEADER):
        # 从已有头文件提取(复用)
        with open(T4_KEY_HEADER) as f:
            content = f.read()
        import re
        m = re.search(r'T4_XOR_KEY\[\]\s*=\s*\{([^}]+)\}', content)
        if m:
            vals = m.group(1).strip().split(',')
            key_hex = ''.join(f'{int(v.strip(), 16):02x}' for v in vals)
            print(f"[1/5] 复用已有密钥: {key_hex[:16]}...")
        else:
            key_hex = os.urandom(16).hex()
            print(f"[1/5] 生成随机密钥: {key_hex[:16]}...")
    else:
        key_hex = os.urandom(16).hex()
        print(f"[1/5] 生成随机密钥: {key_hex[:16]}...")

    # 写 t4_str_key.h
    key_bytes = bytes.fromhex(key_hex)
    key_c = ', '.join(f'0x{b:02x}' for b in key_bytes)
    with open(T4_KEY_HEADER, 'w') as f:
        f.write(f'/* 自动生成 - T4 DEX 字符串解密密钥(ADR 0090) */\n')
        f.write(f'#ifndef T4_STR_KEY_H\n#define T4_STR_KEY_H\n\n')
        f.write(f'#define T4_XOR_KEY_LEN {len(key_bytes)}\n\n')
        f.write(f'static const unsigned char T4_XOR_KEY[] = {{{key_c}}};\n\n')
        f.write(f'#endif /* T4_STR_KEY_H */\n')
    print(f"  t4_str_key.h 已写入")

    if not args.skip_build:
        # Step 2: 构建 defender-sdk(T4_ENABLED=ON)
        print("[2/5] 构建 defender-sdk(T4_ENABLED=ON)...")
        run(f'gradlew assembleRelease -PT4_ENABLED=ON', cwd=SDK_DIR)

        # Step 3: 构建 demo APK
        print("[3/5] 构建 defender-demo...")
        run(f'gradlew assembleRelease', cwd=DEMO_DIR)
    else:
        print("[2/5] 跳过构建(--skip-build)")
        print("[3/5] 跳过构建(--skip-build)")

    # 找到 APK 和 .so
    apk_path = os.path.join(DEMO_DIR, 'build', 'outputs', 'apk', 'release',
                            'defender-demo-release-unsigned.apk')
    so_path = os.path.join(SDK_DIR, 'build', 'intermediates', 'stripped_native_libs',
                           'release', 'stripReleaseDebugSymbols', 'out', 'lib',
                           'arm64-v8a', 'libxcj_defender.so')

    if not os.path.exists(apk_path):
        print(f"ERROR: APK 不存在: {apk_path}")
        sys.exit(1)

    # Step 4: encrypt-strings(修改 DEX)
    print("[4/5] encrypt-strings(修改 DEX)...")
    encrypted_apk = apk_path.replace('.apk', '-t4.apk')
    run(f'java -jar "{INJECTOR_JAR}" encrypt-strings '
        f'--apk "{apk_path}" --output "{encrypted_apk}" '
        f'--key-header "{T4_KEY_HEADER}"')

    # Step 5: patch_x0(在加密后 APK 上计算 hash)
    print("[5/5] patch_x0(方案 A hash 匹配最终态)...")
    patch_script = os.path.join(SCRIPT_DIR, 'patch_x0.py')
    run(f'python "{patch_script}" --apk "{encrypted_apk}" '
        f'--so "{so_path}" --key-hex {key_hex}')

    print(f"\n=== T4 构建完成 ===")
    print(f"输出 APK: {encrypted_apk}")
    print(f"密钥: {key_hex[:16]}...")
    print(f"安装: adb install -r \"{encrypted_apk}\"")


if __name__ == '__main__':
    main()
