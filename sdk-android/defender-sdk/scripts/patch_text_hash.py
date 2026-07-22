#!/usr/bin/env python3
"""
patch_text_hash.py - self_verify .text hash 写入工具(ADR 0088 H1)

编译后运行,计算 .so 的 .text 段 SHA-256,写入 .rodata 的 EXPECTED_TEXT_HASH 占位符,
使运行时 .text 自校验真正生效(占位全 0 时跳过,写入真实 hash 后启用)。

用法:
    python3 patch_text_hash.py libxcj_defender.so

流程:
    1. 解析 ELF section headers,定位 .text 和 .rodata
    2. 计算 .text 段 SHA-256
    3. 在 .rodata 中找 64 个 '0' 的占位符(EXPECTED_TEXT_HASH)
    4. 替换为真实 hash(ASCII hex)
    5. 写回 .so

注意:只写 .rodata 不改 .text,所以 .text hash 不变(自洽)。
应在 strip 之前运行(strip 可能移除 section header)。
"""
import sys
import struct
import hashlib

PLACEHOLDER = b"0" * 64  # EXPECTED_TEXT_HASH 占位符(64 个 ASCII '0')


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    so_path = sys.argv[1]
    with open(so_path, "rb") as f:
        data = bytearray(f.read())

    # 校验 ELF magic
    if data[:4] != b"\x7fELF":
        print(f"错误: {so_path} 不是 ELF 文件")
        sys.exit(1)

    is_64 = data[4] == 2  # ELFCLASS64
    endian = "<" if data[5] == 1 else ">"  # ELFDATA2LSB

    # 解析 ELF header 的 section header table 字段
    if is_64:
        e_shoff = struct.unpack(endian + "Q", data[0x28:0x30])[0]
        e_shentsize = struct.unpack(endian + "H", data[0x3A:0x3C])[0]
        e_shnum = struct.unpack(endian + "H", data[0x3C:0x3E])[0]
        e_shstrndx = struct.unpack(endian + "H", data[0x3E:0x40])[0]
    else:
        e_shoff = struct.unpack(endian + "I", data[0x20:0x24])[0]
        e_shentsize = struct.unpack(endian + "H", data[0x2E:0x30])[0]
        e_shnum = struct.unpack(endian + "H", data[0x30:0x32])[0]
        e_shstrndx = struct.unpack(endian + "H", data[0x32:0x34])[0]

    def read_sh(i: int):
        """读第 i 个 section header,返回 (name_idx, offset, size)"""
        off = e_shoff + i * e_shentsize
        sh_name = struct.unpack(endian + "I", data[off:off + 4])[0]
        if is_64:
            sh_offset = struct.unpack(endian + "Q", data[off + 24:off + 32])[0]
            sh_size = struct.unpack(endian + "Q", data[off + 32:off + 40])[0]
        else:
            sh_offset = struct.unpack(endian + "I", data[off + 16:off + 20])[0]
            sh_size = struct.unpack(endian + "I", data[off + 20:off + 24])[0]
        return sh_name, sh_offset, sh_size

    # section name string table
    _, shstr_off, shstr_size = read_sh(e_shstrndx)
    shstrtab = data[shstr_off:shstr_off + shstr_size]

    def name_at(idx: int) -> str:
        end = shstrtab.index(b"\x00", idx)
        return shstrtab[idx:end].decode()

    # 定位 .text 和 .rodata
    text_offset = text_size = rodata_offset = rodata_size = None
    for i in range(e_shnum):
        sh_name, sh_offset, sh_size = read_sh(i)
        name = name_at(sh_name)
        if name == ".text":
            text_offset, text_size = sh_offset, sh_size
        elif name == ".rodata":
            rodata_offset, rodata_size = sh_offset, sh_size

    if text_offset is None or rodata_offset is None:
        print("错误: 找不到 .text 或 .rodata section(可能已 strip)")
        sys.exit(1)

    # 计算 .text SHA-256
    text_data = bytes(data[text_offset:text_offset + text_size])
    text_hash = hashlib.sha256(text_data).hexdigest()
    print(f".text: offset=0x{text_offset:x} size={text_size}")
    print(f".text SHA-256: {text_hash}")

    # 在 .rodata 找占位符并替换
    rodata = bytes(data[rodata_offset:rodata_offset + rodata_size])
    pos = rodata.find(PLACEHOLDER)
    if pos < 0:
        print("错误: .rodata 中找不到占位符(64 个 '0'),可能已写入真实 hash")
        sys.exit(1)

    abs_pos = rodata_offset + pos
    data[abs_pos:abs_pos + 64] = text_hash.encode("ascii")
    print(f"占位符: .rodata+0x{pos:x} (文件偏移 0x{abs_pos:x})")

    with open(so_path, "wb") as f:
        f.write(data)
    print(f"已写入真实 .text hash 到 {so_path}")


if __name__ == "__main__":
    main()
