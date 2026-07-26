#!/usr/bin/env python3
"""
java_obf.py - Hikari Java/Kotlin 层字符串加密(ADR 0094)

源码级变换:把 .kt/.java 中的字符串字面量替换为 XcjObfStr.d("base64密文"),
JADX/apktool 静态搜索关键词直接失效。

用法:
  python java_obf.py --transform SRC_DIR DST_DIR   # 变换目录下所有 .kt/.java
  python java_obf.py --gen-decrypt DST              # 生成 XcjObfStr.kt 运行时解密类
  python java_obf.py --all SRC_DIR DST_DIR          # 全量:gen-decrypt + transform

构建流水线位置(ADR 0094):
  Gradle 编译前跑 java_obf.py,变换后的源码参与编译,原始源码不动。
"""
import argparse
import base64
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# 跳过的字符串模式
SKIP_PATTERNS = [
    r'^import\s',       # import 语句
    r'^package\s',      # package 声明
    r'^\s*//',          # 注释
    r'^\s*\*',          # 块注释
    r'^\s*@\w+',        # 注解(@Suppress, @JvmStatic 等)
    r'^\s*(private\s+|internal\s+|public\s+)?(const\s+)?val\s+\w+',  # val/const val 声明
    r'.*\bcatch\b',     # catch 块(错误处理不能依赖 XcjObfStr,否则二次 crash)
    r'.*\bthrow\b',     # throw 语句(同上)
    r'.*loadLibrary',   # System.loadLibrary 参数不能加密(鸡生蛋:loadLibrary 前 XcjObfStr 不可用)
    r'.*System\.',      # System.* 调用(同上)
    r'.*bootstrap',     # bootstrap 调用(在 loadLibrary 之后但 XcjObfStr 注册之前)
]

# 跳过的字符串值(太短或无安全意义)
SKIP_VALUES = {
    '', ' ', ',', '.', ':', ';', '/', '\\', '-', '_', '=',
    'true', 'false', 'null',
    'UTF-8', 'application/json',
}

MIN_STRING_LEN = 3  # 短于 3 字符的不加密


def _xor_encrypt(plaintext: str, key: bytes) -> str:
    """XOR 加密 + Base64 编码"""
    data = plaintext.encode('utf-8')
    encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return base64.b64encode(encrypted).decode('ascii')


def _should_skip_line(line: str) -> bool:
    """判断整行是否跳过"""
    for pat in SKIP_PATTERNS:
        if re.match(pat, line):
            return True
    return False


def _should_skip_string(s: str) -> bool:
    """判断字符串值是否跳过"""
    if len(s) < MIN_STRING_LEN:
        return True
    if s in SKIP_VALUES:
        return True
    # 跳过纯数字
    if s.isdigit():
        return True
    # 跳过 format specifier(%s, %d 等)
    if re.match(r'^%[\w.]+$', s):
        return True
    return False


def _obf_template_string(s: str, key: bytes, cls: str, jni_name: str = "d") -> str:
    """处理 Kotlin 模板字符串:静态部分加密,动态部分保留,用 + 拼接。

    支持嵌套花括号(如 ${list.map { it.name }})。
    """
    parts = []  # (is_dynamic, text)
    i = 0
    while i < len(s):
        if s[i] == '$' and i + 1 < len(s):
            if s[i + 1] == '{':
                # ${...} 带嵌套花括号
                depth = 1
                j = i + 2
                while j < len(s) and depth > 0:
                    if s[j] == '{':
                        depth += 1
                    elif s[j] == '}':
                        depth -= 1
                    j += 1
                parts.append((True, s[i + 2:j - 1]))
                i = j
            elif s[i + 1].isalpha() or s[i + 1] == '_':
                # $varName
                j = i + 1
                while j < len(s) and (s[j].isalnum() or s[j] == '_'):
                    j += 1
                parts.append((True, s[i + 1:j]))
                i = j
            else:
                parts.append((False, '$'))
                i += 1
        else:
            # 静态字符,累积到下一个 $
            j = i
            while j < len(s) and s[j] != '$':
                j += 1
            parts.append((False, s[i:j]))
            i = j

    result = []
    for is_dynamic, text in parts:
        if is_dynamic:
            result.append(text)
        else:
            if text and not _should_skip_string(text):
                encrypted = _xor_encrypt(text, key)
                result.append(f'{cls}.{jni_name}("{encrypted}")')
    return " + ".join(result) if result else f'{cls}.d("")'


def _extract_strings(line: str):
    """手动扫描一行,提取所有双引号字符串(支持 ${} 内嵌引号)。

    返回 [(start, end, content), ...] 其中 start/end 是含引号的位置。
    """
    strings = []
    i = 0
    while i < len(line):
        if line[i] == '"':
            # 检查是否是 triple-quoted
            if i + 2 < len(line) and line[i+1] == '"' and line[i+2] == '"':
                # 跳过 triple-quoted
                j = i + 3
                while j + 2 < len(line):
                    if line[j] == '"' and line[j+1] == '"' and line[j+2] == '"':
                        j += 3
                        break
                    j += 1
                i = j
                continue
            # 普通双引号字符串,跟踪 ${} 嵌套
            j = i + 1
            content_start = j
            brace_depth = 0
            while j < len(line):
                c = line[j]
                if c == '\\' and j + 1 < len(line):
                    j += 2  # 跳过转义
                    continue
                if brace_depth > 0:
                    if c == '{':
                        brace_depth += 1
                    elif c == '}':
                        brace_depth -= 1
                    j += 1
                    continue
                if c == '$' and j + 1 < len(line) and line[j+1] == '{':
                    brace_depth = 1
                    j += 2
                    continue
                if c == '"':
                    # 字符串结束
                    strings.append((i, j + 1, line[content_start:j]))
                    j += 1
                    break
                j += 1
            else:
                # 未闭合,跳过
                i += 1
                continue
            i = j
        else:
            i += 1
    return strings


def transform_kotlin(src: str, key: bytes, class_name: str = "XcjObfStr",
                     jni_name: str = "d") -> str:
    """变换 Kotlin/Java 源码中的字符串字面量"""
    lines = src.split('\n')
    out = []
    count = 0

    for line in lines:
        if _should_skip_line(line):
            out.append(line)
            continue

        strings = _extract_strings(line)
        if not strings:
            out.append(line)
            continue

        # 从后往前替换,避免偏移错位
        for start, end, content in reversed(strings):
            if _should_skip_string(content):
                continue
            if '${' in content or re.search(r'\$[a-zA-Z_]', content):
                replacement = _obf_template_string(content, key, class_name, jni_name)
            else:
                encrypted = _xor_encrypt(content, key)
                replacement = f'{class_name}.{jni_name}("{encrypted}")'
            line = line[:start] + replacement + line[end:]
            count += 1

        out.append(line)

    if count > 0:
        print(f"  加密 {count} 个字符串")
    return '\n'.join(out)


def gen_decrypt_class(jni_name: str, package: str = "com.xcj.defender") -> str:
    """生成 XcjObfStr.kt — 纯 external fun 声明,无 key 无解密逻辑。

    解密在 native 层(loader.so)完成,MT 一键解密完全失效。
    """
    return f'''package {package}

/**
 * XcjObfStr - Hikari 字符串解密桩(ADR 0094 防 MT 一键解密)
 *
 * 解密逻辑在 native 层(libxcj_loader.so),DEX 中无 key、无解密代码。
 * MT 的 DEX 一键解密功能完全无法工作。
 * 函数名每构建随机,攻击者不能靠名字定位。
 */
object XcjObfStr {{
    @JvmStatic
    external fun {jni_name}(encoded: String): String
}}
'''


def main():
    ap = argparse.ArgumentParser(description="Hikari Java/Kotlin 字符串加密(ADR 0094)")
    ap.add_argument('--transform', nargs=2, metavar=('SRC_DIR', 'DST_DIR'),
                    help='变换目录下所有 .kt/.java')
    ap.add_argument('--gen-decrypt', metavar='DST',
                    help='生成 XcjObfStr.kt 到指定路径')
    ap.add_argument('--all', nargs=2, metavar=('SRC_DIR', 'DST_DIR'),
                    help='全量:gen-decrypt + transform')
    ap.add_argument('--key-hex', help='XOR 密钥 hex(空=随机生成)')
    ap.add_argument('--package', default='com.xcj.defender',
                    help='XcjObfStr 的包名')
    ap.add_argument('--class-name', default='XcjObfStr',
                    help='替换时用的类名(跨包传全限定名如 com.xcj.defender.XcjObfStr)')
    args = ap.parse_args()

    # 读 native 层 str_key + jni_name(由 native_cff.py --gen-params 生成)
    cpp_dir = os.path.join(HERE, "..", "src", "main", "cpp")
    str_key_hex_path = os.path.join(cpp_dir, "x0_str_key_hex.txt")
    jni_names_h_path = os.path.join(cpp_dir, "x0_jni_names.h")

    jni_name = "d"  # fallback
    if os.path.exists(str_key_hex_path):
        with open(str_key_hex_path, "r") as f:
            key = bytes.fromhex(f.read().strip())
        print(f"[hikari] 读取 native str_key: {key.hex()}")
    elif args.key_hex:
        key = bytes.fromhex(args.key_hex)
    else:
        key = bytes(random.randint(0, 255) for _ in range(16))
        print(f"[hikari] 随机密钥: {key.hex()}")

    if os.path.exists(jni_names_h_path):
        with open(jni_names_h_path, "r") as f:
            m = re.search(r'X0_JNI_STR_DECRYPT_NAME\s+"([^"]+)"', f.read())
            if m:
                jni_name = m.group(1)
        print(f"[hikari] JNI 解密函数名: {jni_name}")

    # 生成解密类(纯 external fun 声明)
    if args.gen_decrypt or args.all:
        dst = args.gen_decrypt or os.path.join(args.all[1], 'XcjObfStr.kt')
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, 'w', encoding='utf-8', newline='\n') as f:
            f.write(gen_decrypt_class(jni_name, args.package))
        print(f"[hikari] 解密桩 -> {dst} (jni_name={jni_name})")

    # 变换源码
    src_dst = args.transform or args.all
    if src_dst:
        src_dir, dst_dir = src_dst
        total = 0
        for root, dirs, files in os.walk(src_dir):
            for fname in files:
                if not (fname.endswith('.kt') or fname.endswith('.java')):
                    continue
                src_path = os.path.join(root, fname)
                rel = os.path.relpath(src_path, src_dir)
                dst_path = os.path.join(dst_dir, rel)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)

                with open(src_path, 'r', encoding='utf-8') as f:
                    src = f.read()
                out = transform_kotlin(src, key, args.class_name, jni_name)
                with open(dst_path, 'w', encoding='utf-8', newline='\n') as f:
                    f.write(out)
                total += 1
                print(f"  {rel}")

        print(f"[hikari] 变换 {total} 个文件")


if __name__ == '__main__':
    main()
