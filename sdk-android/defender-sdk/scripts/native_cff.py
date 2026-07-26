#!/usr/bin/env python3
"""
native_cff.py - Hikari 控制流混淆框架(ADR 0094)

MVP 功能(直接对抗 RC4 key 静态提取):
  1. 生成 CFF 随机参数 → cff_params.h(状态表 + LCG 参数,每构建随机)
  2. 生成密钥派生材料 → x0_derive.h(salt + XOR 碎片 + 伪调用参数)
  3. 数字混淆:源码中整数常量 → 等价算术表达式(运行时计算,IDA 看不到立即数)

构建流水线位置(ADR 0094 §8):
  SDK 源码 → native_cff.py(CFF+数字混淆) → obfstr_poly.py(X1) → CMake → .so

用法:
  python native_cff.py --gen-params          # 生成 cff_params.h + x0_derive.h
  python native_cff.py --number-obf SRC DST  # 数字混淆(读 SRC 输出 DST)
  python native_cff.py --all SRC DST         # 全量:gen-params + number-obf
"""
import argparse
import json
import os
import random
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CPP = os.path.join(HERE, "..", "src", "main", "cpp")
HIKARI_JSON = os.path.join(HERE, "hikari.json")

# =====================================================================
# 1. CFF 随机参数生成
# =====================================================================

def _is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def _random_prime(lo, hi):
    while True:
        p = random.randint(lo, hi)
        if _is_prime(p):
            return p


def gen_cff_params(cfg):
    """生成 CFF 随机参数 → cff_params.h

    包含:
      - CFF_TABLE[256]: 随机查找表(奇数步查表用)
      - CFF_A / CFF_B / CFF_P: LCG 参数(偶数步用)
      - CFF_INIT: 初始状态(构建期随机)
      - CFF_EXIT: 终止状态
      - CFF_BOGUS_*: 不透明谓词参数(僵尸代码用)
    """
    state_count = cfg.get("state_count", 16)

    # 随机状态值(16 位,避免 0 和 0xFFFF)
    states = random.sample(range(1, 0xFFFE), state_count + 2)
    init_state = states[0]
    exit_state = states[-1]
    body_states = states[1:-1]

    # 随机查找表(256 条目,16 位)
    table = [random.randint(0, 0xFFFF) for _ in range(256)]
    # 确保表中有 body_states 的值(保证可达性)
    for i, s in enumerate(body_states):
        table[random.randint(0, 255)] = s

    # LCG 参数:state = (A * state + B) % P
    prime = _random_prime(0xFFF0, 0xFFFE)  # 16 位素数
    a = random.randint(1, prime - 1)
    b = random.randint(0, prime - 1)

    # 不透明谓词参数:x^2 + y^2 >= 0 恒真,但反编译器难推导
    bogus_x = random.randint(1, 0xFFFF)
    bogus_y = random.randint(1, 0xFFFF)
    bogus_z = random.randint(1, 0xFFFF)

    # 多状态变量(8 条):stateA/B/C 协同
    state_a_init = random.randint(1, 0xFFFE)
    state_b_init = random.randint(1, 0xFFFE)
    state_c_init = random.randint(1, 0xFFFE)

    table_str = ",\n    ".join(
        ", ".join(f"0x{table[i+j]:04x}" for j in range(8))
        for i in range(0, 256, 8)
    )

    content = f"""/* cff_params.h - native_cff.py 生成,勿手改。
 * Hikari CFF 随机参数(ADR 0094 §5)。每构建随机,二进制不可复现。
 */
#ifndef CFF_PARAMS_H
#define CFF_PARAMS_H

#include <stdint.h>

/* === 状态转移查找表(奇数步)== */
static const uint16_t CFF_TABLE[256] = {{
    {table_str}
}};

/* === LCG 参数(偶数步):state = (A * state + B) % P == */
#define CFF_A  0x{a:04x}u
#define CFF_B  0x{b:04x}u
#define CFF_P  0x{prime:04x}u

/* === 初始 / 终止状态 == */
#define CFF_INIT  0x{init_state:04x}u
#define CFF_EXIT  0x{exit_state:04x}u

/* === 基本块状态值(构建期随机分配)== */
"""
    for i, s in enumerate(body_states):
        content += f"#define CFF_S{i}  0x{s:04x}u\n"

    content += f"""
/* === 不透明谓词参数(僵尸代码 / BCF)==
 * x^2 + y^2 >= 0 恒真,但反编译器算不出来。
 */
#define CFF_BOGUS_X  0x{bogus_x:04x}u
#define CFF_BOGUS_Y  0x{bogus_y:04x}u
#define CFF_BOGUS_Z  0x{bogus_z:04x}u

/* === 多状态变量初始值(8 条:stateA/B/C 协同)== */
#define CFF_SA_INIT  0x{state_a_init:04x}u
#define CFF_SB_INIT  0x{state_b_init:04x}u
#define CFF_SC_INIT  0x{state_c_init:04x}u

/* === 状态转移函数(奇偶步交替,ADR 0094 §5 方案 c)== */
static inline uint16_t cff_next(uint16_t state, int step) {{
    if (step & 1) {{
        /* 奇数步:查表 */
        return CFF_TABLE[state & 0xFF] ^ (uint16_t)(state >> 8);
    }} else {{
        /* 偶数步:LCG */
        return (uint16_t)(((uint32_t)CFF_A * state + CFF_B) % CFF_P);
    }}
}}

/* === 不透明谓词:恒真但难推导 == */
static inline int cff_opaque_true(uint32_t x) {{
    /* x^2 >= 0 对 unsigned 恒真;反编译器无法证明 */
    return (x * x + CFF_BOGUS_X * CFF_BOGUS_Y) >= 0;
}}

static inline int cff_opaque_false(uint32_t x) {{
    /* x^2 + 1 == 0 对 unsigned 恒假;反编译器无法证明 */
    return (x * x + 1u) == 0u;
}}

#endif /* CFF_PARAMS_H */
"""
    return content


# =====================================================================
# 2. 密钥派生材料生成
# =====================================================================

def gen_derive_material(key_hex, salt_bytes=32):
    """生成密钥派生材料 → x0_derive.h

    包含:
      - X0_SALT[32]: 构建期随机 salt(伪装成"日志种子")
      - X0_KEY_XOR[32]: key ⊕ salt(运行时再 ⊕ 回来)
      - X0_KEY_FRAG[4][8]: key 拆 4 段散布(伪装成不同用途)
      - X0_BUILD_ID_PAD: build_id 的 XOR pad

    运行时派生:
      derived_key[i] = X0_KEY_XOR[i] ⊕ (SO_base ⊕ text_crc ⊕ build_id ⊕ salt)[i%4]
    """
    key = bytes.fromhex(key_hex)
    salt = bytes(random.randint(0, 255) for _ in range(salt_bytes))

    # key ⊕ salt
    key_xor = bytes(k ^ s for k, s in zip(key, salt))

    # key 拆 4 段(每段 8 字节)
    frags = [key[i:i+8] for i in range(0, 32, 8)]

    # build_id pad(随机 4 字节)
    build_pad = bytes(random.randint(0, 255) for _ in range(4))

    def hex_arr(b, name, per_line=8):
        lines = []
        for i in range(0, len(b), per_line):
            chunk = b[i:i+per_line]
            lines.append("    " + ", ".join(f"0x{x:02x}" for x in chunk))
        return f"static const uint8_t {name}[{len(b)}] = {{\n" + ",\n".join(lines) + "\n};\n"

    content = f"""/* x0_derive.h - native_cff.py 生成,勿手改。
 * 密钥派生材料(ADR 0094 §2-3)。
 *
 * 运行时派生公式:
 *   pad[i] = (so_base ^ text_crc ^ build_id ^ salt)[i % 4]
 *   key[i] = X0_KEY_XOR[i] ^ pad[i]
 *
 * 伪装说明:
 *   X0_SALT     → 伪装成"日志去重种子"(xcj_init_log_seed)
 *   X0_KEY_FRAG → 伪装成"ABI 兼容标志"(xcj_check_abi_compat)
 *   X0_BUILD_PAD → 伪装成"ELF 校验偏移"(xcj_verify_elf_offset)
 */
#ifndef X0_DERIVE_H
#define X0_DERIVE_H

#include <stdint.h>

/* "日志去重种子"(实际:salt) */
{hex_arr(salt, "X0_SALT")}
/* "ABI 兼容标志"(实际:key ⊕ salt) */
{hex_arr(key_xor, "X0_KEY_XOR")}
/* "ELF 校验偏移"(实际:build_id XOR pad) */
{hex_arr(build_pad, "X0_BUILD_PAD")}
/* 密钥碎片(拆 4 段散布,实际:key 明文分段) */
"""
    for i, frag in enumerate(frags):
        content += hex_arr(frag, f"X0_KEY_FRAG{i}")

    content += f"""
#define X0_SALT_LEN     {salt_bytes}
#define X0_KEY_XOR_LEN  {len(key_xor)}
#define X0_BUILD_PAD_LEN {len(build_pad)}
#define X0_FRAG_COUNT   4
#define X0_FRAG_SIZE    8

#endif /* X0_DERIVE_H */
"""
    return content


# =====================================================================
# 3. 数字混淆:整数常量 → 等价算术表达式
# =====================================================================

def _obf_number(n):
    """把整数 n 变成等价算术表达式(运行时计算,IDA 看不到立即数)。

    随机选一种变换:
      (a) n = (n+delta) - delta
      (b) n = (n ^ mask) ^ mask
      (c) n = (n << shift) >> shift  (仅 n 不溢出时)
      (d) n = (n * 3) / 3  (仅 n 整除时)
    """
    if n == 0:
        return "0"

    choice = random.randint(0, 3)

    if choice == 0:
        # 加减
        delta = random.randint(1, 0xFFFF)
        return f"((0x{n + delta:x}u) - 0x{delta:x}u)"
    elif choice == 1:
        # XOR
        mask = random.randint(1, 0xFFFF)
        return f"((0x{n ^ mask:x}u) ^ 0x{mask:x}u)"
    elif choice == 2 and n < 0x40000000:
        # 移位
        shift = random.randint(1, 8)
        return f"((0x{n << shift:x}u) >> {shift})"
    else:
        # 乘除
        m = random.choice([3, 5, 7, 9, 11, 13])
        return f"((0x{n * m:x}u) / {m}u)"


def number_obf_source(src):
    """对 C 源码中的整数常量做数字混淆(十六进制 + 十进制)。

    替换范围:
      - #define 行中的十六进制(0xNNNN)和十进制常量
      - 赋值/比较语句中的十六进制常量
    跳过:注释、字符串、数组初始化器(已由 cff_params.h/x0_derive.h 处理)。
    """
    lines = src.split("\n")
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            out.append(line)
            continue
        if '"' in line:
            out.append(line)
            continue

        if "#define" in line:
            # #define 行:混淆十六进制 + 十进制(仅替换行末数值,不碰宏名和表达式)
            def repl_hex(m):
                val = int(m.group(0).rstrip('uU'), 16)
                if val <= 1 or val > 0xFFFFFFFF:
                    return m.group(0)
                return _obf_number(val)
            line = re.sub(r'0x[0-9a-fA-F]+[uU]?', repl_hex, line)
            # 十进制:只替换 #define NAME 后面的纯数字值(如 #define THRESHOLD 70)
            def repl_dec(m):
                val = int(m.group(2))
                if val <= 1 or val > 0xFFFFFFFF:
                    return m.group(0)
                return m.group(1) + _obf_number(val) + (m.group(3) or "")
            line = re.sub(r'(#define\s+\w+\s+)(\d+)(\s*)$', repl_dec, line)

        elif "=" in line or "==" in line or "!=" in line or ">=" in line or "<=" in line:
            # 赋值/比较:只混淆十六进制
            def repl_hex2(m):
                val = int(m.group(0).rstrip('uU'), 16)
                if val <= 1 or val > 0xFFFFFFFF:
                    return m.group(0)
                return _obf_number(val)
            line = re.sub(r'0x[0-9a-fA-F]+[uU]?', repl_hex2, line)

        out.append(line)
    return "\n".join(out)


# =====================================================================
# 4. 字符串解密 native 层材料(ADR 0094 防 MT 一键解密)
# =====================================================================

def _random_jni_name(length=8):
    """生成随机 JNI 函数名(字母开头,含字母数字)"""
    first = random.choice("abcdefghijklmnopqrstuvwxyz")
    rest = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(length - 1))
    return first + rest


def gen_str_key_and_jni(str_key_hex=None):
    """生成 x0_str_key.h + x0_jni_names.h

    x0_str_key.h: 字符串 XOR key 碎片(4 段,每段 4 字节,共 16 字节)
    x0_jni_names.h: 随机 JNI 函数名(每构建不同)

    运行时:loader.so 的 CFF 保护函数从碎片重建 str_key,
    解密 Java 层传入的 Base64 密文。
    """
    if str_key_hex:
        str_key = bytes.fromhex(str_key_hex)
    else:
        str_key = bytes(random.randint(0, 255) for _ in range(16))

    # 拆 4 段
    frags = [str_key[i:i+4] for i in range(0, 16, 4)]

    # 随机 XOR pad(每段一个,运行时碎片 ⊕ pad 还原)
    pads = [bytes(random.randint(0, 255) for _ in range(4)) for _ in range(4)]
    masked = [bytes(f ^ p for f, p in zip(frags[i], pads[i])) for i in range(4)]

    def hex_arr4(b, name):
        return f"static const uint8_t {name}[4] = {{ {', '.join(f'0x{x:02x}' for x in b)} }};\n"

    jni_name = _random_jni_name()

    content_key = f"""/* x0_str_key.h - native_cff.py 生成,勿手改。
 * 字符串解密 key 碎片(ADR 0094,防 MT 一键解密)。
 * 运行时重建:str_key = (MASKED0 ⊕ PAD0) || (MASKED1 ⊕ PAD1) || ...
 */
#ifndef X0_STR_KEY_H
#define X0_STR_KEY_H
#include <stdint.h>
#define X0_STR_KEY_LEN 16

/* 碎片掩码(运行时 ⊕ PAD 还原) */
{hex_arr4(masked[0], "X0_STRK_M0")}
{hex_arr4(masked[1], "X0_STRK_M1")}
{hex_arr4(masked[2], "X0_STRK_M2")}
{hex_arr4(masked[3], "X0_STRK_M3")}

/* XOR pad */
{hex_arr4(pads[0], "X0_STRK_P0")}
{hex_arr4(pads[1], "X0_STRK_P1")}
{hex_arr4(pads[2], "X0_STRK_P2")}
{hex_arr4(pads[3], "X0_STRK_P3")}

#endif /* X0_STR_KEY_H */
"""

    content_jni = f"""/* x0_jni_names.h - native_cff.py 生成,勿手改。
 * 随机 JNI 函数名(ADR 0094,防 MT 按名称定位解密函数)。
 * 每构建随机,攻击者不能靠名字定位。
 */
#ifndef X0_JNI_NAMES_H
#define X0_JNI_NAMES_H

#define X0_JNI_STR_DECRYPT_NAME "{jni_name}"

#endif /* X0_JNI_NAMES_H */
"""

    return content_key, content_jni, str_key, jni_name


# =====================================================================
# main
# =====================================================================

def main():
    ap = argparse.ArgumentParser(description="Hikari CFF 混淆框架(ADR 0094)")
    ap.add_argument("--gen-params", action="store_true",
                    help="生成 cff_params.h + x0_derive.h")
    ap.add_argument("--key-hex", help="RC4 密钥 hex(供 --gen-params 生成派生材料)")
    ap.add_argument("--number-obf", nargs=2, metavar=("SRC", "DST"),
                    help="数字混淆:读 SRC 输出 DST")
    ap.add_argument("--all", nargs=2, metavar=("SRC", "DST"),
                    help="全量:gen-params + number-obf")
    ap.add_argument("--config", default=HIKARI_JSON, help="hikari.json 路径")
    args = ap.parse_args()

    # 读配置
    cfg = {}
    if os.path.exists(args.config):
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = json.load(f)

    if args.gen_params or args.all:
        # 生成 cff_params.h
        cff_cfg = cfg.get("cff", {})
        cff_h = gen_cff_params(cff_cfg)
        cff_path = os.path.join(CPP, "cff_params.h")
        with open(cff_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(cff_h)
        print(f"[hikari] CFF 参数 -> {cff_path}")

        # 生成 x0_derive.h(需要 key)
        key_hex = args.key_hex
        if not key_hex:
            # 从 x0_key.h 读
            key_h = os.path.join(CPP, "x0_key.h")
            if os.path.exists(key_h):
                with open(key_h, "r") as f:
                    text = f.read()
                m = re.search(r"X0_KEY\[X0_KEY_LEN\]\s*=\s*\{([^}]*)\}", text)
                if m:
                    key_hex = "".join(re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))
        if key_hex:
            salt_bytes = cfg.get("salt_bytes", 32)
            derive_h = gen_derive_material(key_hex, salt_bytes)
            derive_path = os.path.join(CPP, "x0_derive.h")
            with open(derive_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(derive_h)
            print(f"[hikari] 派生材料 -> {derive_path}")
        else:
            print("[hikari] 警告:未提供 key,跳过 x0_derive.h 生成")

        # 生成 x0_str_key.h + x0_jni_names.h(字符串解密 native 层)
        str_key_h, jni_names_h, str_key, jni_name = gen_str_key_and_jni()
        with open(os.path.join(CPP, "x0_str_key.h"), "w", encoding="utf-8", newline="\n") as f:
            f.write(str_key_h)
        with open(os.path.join(CPP, "x0_jni_names.h"), "w", encoding="utf-8", newline="\n") as f:
            f.write(jni_names_h)
        print(f"[hikari] 字符串 key 碎片 -> x0_str_key.h, JNI 名={jni_name}")

        # 写 str_key hex 到临时文件供 java_obf.py 读取
        sk_path = os.path.join(CPP, "x0_str_key_hex.txt")
        with open(sk_path, "w") as f:
            f.write(str_key.hex())

    src_dst = args.number_obf or args.all
    if src_dst:
        src_path, dst_path = src_dst
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        out = number_obf_source(src)
        with open(dst_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(out)
        print(f"[hikari] 数字混淆: {src_path} -> {dst_path}")


if __name__ == "__main__":
    main()
