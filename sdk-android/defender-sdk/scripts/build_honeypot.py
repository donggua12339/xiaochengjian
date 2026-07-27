#!/usr/bin/env python3
"""
build_honeypot.py - 构建期生成诱饵字符串(天衍 Honeypot)

在 .rodata 中植入看起来像真实密钥/URL/配置的假字符串。
攻击者用 strings/IDA 搜索时会找到这些,花数小时验证后发现是诱饵。

对抗效果:
  - 静态分析(strings/grep): 找到 "API_KEY=..." 但实际无功能
  - IDA xref: 追踪引用发现是 dead code
  - 自动化密钥提取: 提取出的 "密钥" 解密后是垃圾

用法:
    python scripts/build_honeypot.py --output honeypot_strings.h [--seed 42]
"""
import argparse
import hashlib
import random
import string
import time


def gen_fake_key(rng: random.Random, length: int = 32) -> str:
    chars = string.hexdigits[:16]  # 0-9a-f
    return ''.join(rng.choice(chars) for _ in range(length))


def gen_fake_url(rng: random.Random) -> str:
    domains = [
        "api.xcj-internal.dev", "license.winmelon.cn",
        "auth.xiaochengjian.io", "key-server.xcj.cloud",
        "verify.defender-sdk.net", "heartbeat.xcj-protect.com",
    ]
    paths = ["/v2/license/check", "/api/key/validate", "/auth/verify",
             "/internal/heartbeat", "/sdk/activate"]
    return f"https://{rng.choice(domains)}{rng.choice(paths)}"


def gen_fake_config(rng: random.Random) -> str:
    return (
        f'{{"server":"{gen_fake_url(rng)}",'
        f'"key":"{gen_fake_key(rng, 64)}",'
        f'"salt":"{gen_fake_key(rng, 16)}",'
        f'"version":{rng.randint(2,5)},'
        f'"debug":false}}'
    )


def generate_honeypot_header(seed: int) -> str:
    rng = random.Random(seed)

    # 生成诱饵数据
    fake_api_keys = [gen_fake_key(rng, 32) for _ in range(3)]
    fake_urls = [gen_fake_url(rng) for _ in range(3)]
    fake_configs = [gen_fake_config(rng) for _ in range(2)]
    fake_rsa_header = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA" + gen_fake_key(rng, 48) + "\\n..."

    lines = []
    lines.append('/**')
    lines.append(' * honeypot_strings.h - 诱饵字符串(自动生成,请勿手动修改)')
    lines.append(f' * 由 build_honeypot.py 生成 | seed={seed}')
    lines.append(' *')
    lines.append(' * 这些字符串看起来像真实密钥/URL/配置,实际是无功能的诱饵。')
    lines.append(' * 目的: 浪费攻击者静态分析时间。')
    lines.append(' */')
    lines.append('#ifndef HONEYPOT_STRINGS_H')
    lines.append('#define HONEYPOT_STRINGS_H')
    lines.append('')
    lines.append('#include <stdint.h>')
    lines.append('')

    # 用 volatile 防止编译器优化掉
    lines.append('/* 诱饵 API 密钥(看起来像真密钥,实际无功能) */')
    for i, key in enumerate(fake_api_keys):
        lines.append(f'static volatile const char *const HONEYPOT_KEY_{i} = "{key}";')
    lines.append('')

    lines.append('/* 诱饵 URL(看起来像服务器地址,实际不存在) */')
    for i, url in enumerate(fake_urls):
        lines.append(f'static volatile const char *const HONEYPOT_URL_{i} = "{url}";')
    lines.append('')

    lines.append('/* 诱饵配置 JSON(看起来像加密配置,实际是垃圾) */')
    for i, cfg in enumerate(fake_configs):
        escaped = cfg.replace('"', '\\"')
        lines.append(f'static volatile const char *const HONEYPOT_CFG_{i} = "{escaped}";')
    lines.append('')

    lines.append(f'static volatile const char *const HONEYPOT_RSA = "{fake_rsa_header}";')
    lines.append('')

    # 死引用: 确保字符串不被 gc-sections 移除(不用 constructor,避免干扰 cl 加载)
    lines.append('/* 死引用: 确保诱饵字符串保留在 .rodata */')
    lines.append('static volatile const void *const honeypot_anchors[] __attribute__((used)) = {')
    for i in range(len(fake_api_keys)):
        lines.append(f'    (const void *)HONEYPOT_KEY_{i},')
    for i in range(len(fake_urls)):
        lines.append(f'    (const void *)HONEYPOT_URL_{i},')
    lines.append('    NULL')
    lines.append('};')
    lines.append('')
    lines.append('#endif /* HONEYPOT_STRINGS_H */')

    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='Honeypot 诱饵字符串生成')
    parser.add_argument('--output', '-o', default='honeypot_strings.h')
    parser.add_argument('--seed', type=int, default=int(time.time()))
    args = parser.parse_args()

    print(f"=== Honeypot 诱饵字符串 | seed={args.seed} ===")
    header = generate_honeypot_header(args.seed)
    with open(args.output, 'w') as f:
        f.write(header)
    print(f"输出: {args.output}")
    print("完成!")


if __name__ == '__main__':
    main()
