#!/usr/bin/env python3
"""
obfstr_poly.py - 玄甲 X1 字符串多态加密(构建期加密 + 源码扫描替换)

详见 docs/PRODUCT_XUANJIA_TIANYAN.md §5 + ADR 0091 §3.2

功能:
  1. encrypt(plain, seed, variant) -> cipher  (与 obfstr_poly.h 的 decode 严格互逆)
  2. transform_source(text) -> text            (扫描 OBF("...") 替换为 _OBF_USE(...))
  3. 生成 test_vectors_generated.h             (供 C 端交叉验证 C_decode ∘ py_encrypt == id)
  4. __main__ 自测:py 自洽 + 生成 vectors

原语集/排列/参数派生 必须与 obfstr_poly.h 逐字一致。
  op0=XOR  op1=ROL  op2=ADD  op3=MUL(mod 256, 乘数奇数且非1; ROL 8 位)
  per-string(非退化映射,保证每原语非恒等):
    xk=((seed)&0xff)|1  rn=((seed>>8)&7)|1  ak=((seed>>16)&0xff)|1
    mk=((seed>>19)&0xff)|1; if mk==1: mk=3
  注:早期 op3 用 SUB,与 ADD 互逆致排列坍缩,改 MUL 修复(见 obfstr_poly.h 头部说明)。
"""
import os
import re
import random

# ============= 24 排列(与 obfstr_poly.h 严格一致) =============
PERM = [
    (0, 1, 2, 3), (0, 1, 3, 2), (0, 2, 1, 3), (0, 2, 3, 1), (0, 3, 1, 2), (0, 3, 2, 1),
    (1, 0, 2, 3), (1, 0, 3, 2), (1, 2, 0, 3), (1, 2, 3, 0), (1, 3, 0, 2), (1, 3, 2, 0),
    (2, 0, 1, 3), (2, 0, 3, 1), (2, 1, 0, 3), (2, 1, 3, 0), (2, 3, 0, 1), (2, 3, 1, 0),
    (3, 0, 1, 2), (3, 0, 2, 1), (3, 1, 0, 2), (3, 1, 2, 0), (3, 2, 0, 1), (3, 2, 1, 0),
]


def _params(seed: int):
    xk = (seed & 0xff) | 1
    rn = ((seed >> 8) & 0x7) | 1
    ak = ((seed >> 16) & 0xff) | 1
    mk = ((seed >> 19) & 0xff) | 1
    mk = 3 if mk == 1 else mk
    return xk, rn, ak, mk


def _rol8(x: int, n: int) -> int:
    n &= 7
    return ((x << n) | (x >> ((8 - n) & 7))) & 0xff


def _fwd(op: int, b: int, xk: int, rn: int, ak: int, mk: int) -> int:
    if op == 0:
        return b ^ xk
    if op == 1:
        return _rol8(b, rn)
    if op == 2:
        return (b + ak) & 0xff
    if op == 3:
        return (b * mk) & 0xff
    return b


def _inv(op: int, b: int, xk: int, rn: int, ak: int, mk: int) -> int:
    if op == 0:
        return b ^ xk
    if op == 1:
        return _rol8(b, (8 - rn) & 7)
    if op == 2:
        return (b - ak) & 0xff
    if op == 3:
        return (b * pow(mk, -1, 256)) & 0xff
    return b


def encrypt(plain: bytes, seed: int, variant: int) -> bytes:
    xk, rn, ak, mk = _params(seed)
    perm = PERM[variant & 0x1f]
    out = bytearray()
    for b in plain:
        b = _fwd(perm[0], b, xk, rn, ak, mk)
        b = _fwd(perm[1], b, xk, rn, ak, mk)
        b = _fwd(perm[2], b, xk, rn, ak, mk)
        b = _fwd(perm[3], b, xk, rn, ak, mk)
        out.append(b)
    return bytes(out)


def decrypt(cipher: bytes, seed: int, variant: int) -> bytes:
    xk, rn, ak, mk = _params(seed)
    perm = PERM[variant & 0x1f]
    out = bytearray()
    for b in cipher:
        b = _inv(perm[3], b, xk, rn, ak, mk)
        b = _inv(perm[2], b, xk, rn, ak, mk)
        b = _inv(perm[1], b, xk, rn, ak, mk)
        b = _inv(perm[0], b, xk, rn, ak, mk)
        out.append(b)
    return bytes(out)


# ============= 源码扫描替换 =============
# 匹配 OBF("...") 或 OBF('...')(不含转义引号的简单字面量;复杂串后续扩展)
_OBF_RE = re.compile(r'''OBF\(\s*"((?:[^"\\]|\\.)*)"\s*\)''')


def _c_escape_byte(b: int) -> str:
    return f"0x{b:02X}"


def transform_source(text: str, rng: random.Random) -> str:
    """把每个 OBF("lit") 替换为 _OBF_USE(seed,variant,n,{cipher...})。"""
    def repl(m: re.Match) -> str:
        lit = m.group(1)
        # 解 C 转义(简化:支持 \\, \", \n, \t, \0, \xNN)
        plain = lit.encode("utf-8").decode("unicode_escape").encode("latin-1")
        seed = rng.randint(0, 0x00FFFFFF)
        variant = rng.randint(0, 23)
        cipher = encrypt(plain, seed, variant)
        n = len(plain)
        cbytes = ",".join(_c_escape_byte(b) for b in cipher)
        return f"_OBF_USE(0x{seed:08X}u,{variant}u,{n}u,{cbytes})"
    return _OBF_RE.sub(repl, text)


# ============= 生成 C 交叉验证向量 =============
def gen_test_vectors(out_path: str, rng: random.Random, count: int = 48) -> None:
    samples = [b"frida", b"/proc/self/maps", b"libfrida-agent.so",
               b"TracerPid", b"xposed", b"com.xcj.defender", b"", b"A",
               b"signature_verify_mmap", b"android_dlopen_ext"]
    lines = []
    lines.append("/* 自动生成,勿手改。由 obfstr_poly.py 产出,供 test_obfstr_poly.c 交叉验证 */")
    lines.append("#ifndef OBF_TEST_VECTORS_GENERATED_H")
    lines.append("#define OBF_TEST_VECTORS_GENERATED_H")
    lines.append("typedef struct { const char *plain; uint32_t seed; uint8_t variant; "
                 "size_t n; const uint8_t *cipher; } obf_vec_t;")
    lines.append(f"static const int OBF_VEC_COUNT = {count};")
    # 先收集
    vecs = []
    for i in range(count):
        plain = samples[i % len(samples)]
        seed = rng.randint(0, 0x00FFFFFF)
        variant = rng.randint(0, 23)
        cipher = encrypt(plain, seed, variant)
        vecs.append((plain, seed, variant, cipher))
    # 每个 cipher 数组
    for i, (plain, seed, variant, cipher) in enumerate(vecs):
        cbytes = ",".join(_c_escape_byte(b) for b in cipher) if cipher else "0"
        lines.append(f"static const uint8_t _obf_v{i}[] = {{{cbytes}}};")
    lines.append("static const obf_vec_t OBF_VECS[] = {")
    for i, (plain, seed, variant, cipher) in enumerate(vecs):
        p_esc = plain.replace(b"\\", b"\\\\").replace(b"\"", b"\\\"")
        p_cstr = p_esc.decode("latin-1")
        lines.append(f'    {{"{p_cstr}", 0x{seed:08X}u, {variant}u, {len(plain)}u, _obf_v{i}}},')
    lines.append("};")
    lines.append("#endif")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")


# ============= 自测 =============
def _self_test(rng: random.Random) -> None:
    # py 自洽:decrypt(encrypt(p)) == p,遍历全部 24 variant + 多 seed + 多明文
    samples = [b"frida", b"/proc/self/maps", b"", b"\x00\x01\xff", b"x" * 200,
               b"com.xcj.defender.demo", b"TracerPid:", b"android_dlopen_ext"]
    for variant in range(24):
        for _ in range(8):
            seed = rng.randint(0, 0x00FFFFFF)
            for p in samples:
                c = encrypt(p, seed, variant)
                assert decrypt(c, seed, variant) == p, (variant, seed, p)
                # 多态性:不同 (seed,variant) 产生不同密文(除非偶然)
    # 多态差异:同明文不同参数 -> 密文不同(抽样)
    p = b"frida"
    c0 = encrypt(p, 0x00010203, 0)
    c1 = encrypt(p, 0x00010203, 1)
    c2 = encrypt(p, 0x00FFFFFF, 0)
    assert c0 != c1 and c0 != c2, "多态性失效"
    # .rodata 无明文:密文不等于明文
    assert c0 != p
    # 非退化:每原语在派生参数下不为恒等(抽样验证 MUL 逆正确性)
    for _ in range(64):
        seed = rng.randint(0, 0x00FFFFFF)
        xk, rn, ak, mk = _params(seed)
        assert xk != 0 and rn != 0 and ak != 0 and mk != 1 and (mk & 1) == 1
        assert (mk * pow(mk, -1, 256)) & 0xff == 1
    print(f"[obfstr_poly] py 自洽通过:24 variant × 8 seed × {len(samples)} plain 全往返正确;"
          f"多态差异确认;非退化映射确认")


def transform_file(in_path: str, out_path: str, rng: random.Random) -> int:
    """构建期:读 IN,把 OBF("...") 替换为 _OBF_USE(...) 写入 OUT。返回替换处数。"""
    with open(in_path, "r", encoding="utf-8") as f:
        text = f.read()
    out_text = transform_source(text, rng)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(out_text)
    return len(_OBF_RE.findall(text))


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="玄甲 X1 字符串多态加密(构建期加密 + 源码扫描替换)")
    parser.add_argument("--transform", nargs=2, metavar=("IN", "OUT"),
                        help="构建期:扫描 IN 中 OBF(\"...\") 替换为 _OBF_USE(...) 写入 OUT")
    parser.add_argument("--seed", type=int, default=None,
                        help="transform 随机种子;默认 os.urandom(每构建不同密文),CI 可固定以便复现")
    args = parser.parse_args()

    if args.transform:
        in_path, out_path = args.transform
        if args.seed is not None:
            rng = random.Random(args.seed)
        else:
            rng = random.Random(int.from_bytes(os.urandom(8), "big"))
        n = transform_file(in_path, out_path, rng)
        print(f"[obfstr_poly] transform: {in_path} -> {out_path}, 替换 {n} 处 OBF()")
        return

    # 默认:自测 + 生成 vectors(固定种子可复现)
    rng = random.Random(0xC0FFEE)
    _self_test(rng)
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "..", "src", "main", "cpp", "tests", "test_vectors_generated.h")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    gen_test_vectors(out, rng, count=48)
    print(f"[obfstr_poly] 已生成 {out}")


if __name__ == "__main__":
    main()
