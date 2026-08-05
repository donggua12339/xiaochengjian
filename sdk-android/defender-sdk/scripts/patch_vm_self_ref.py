#!/usr/bin/env python3
"""
patch_vm_self_ref.py - VM 自引用 CRC 构建期写入(ADR 0098 P0-C)

链接后运行(POST_BUILD,此时未 strip,.symtab 在场),定位 vmself_code 区段
计算 CRC-32,写入 .rodata 的 VMSREF01 占位符,使运行时 VM 引擎自引用校验生效。

定位策略(按优先级):
  1. .symtab 符号 __start_vmself_code / __stop_vmself_code(与运行时
     vm_self_ref_compute_crc 完全同一范围;lld 可能把 vmself_code 输入段
     并进 .text 输出段,按节名找不可靠,故符号优先)。
  2. 回退:按节名 vmself_code 找 section(GNU ld 保留独立段时可用)。

自洽性:占位符在 .rodata(区段外),写入不改变区段字节 → CRC 稳定。
注意:CMakeLists 不能 -Wl,-s(会抹 .symtab);release strip 由 Gradle
stripReleaseDebugSymbols 在 POST_BUILD 之后执行,不冲突。
"""
import sys
import struct
import zlib

ANCHOR = b"VMSREF01"
SECTION_NAME = b"vmself_code"
SYM_START = b"__start_vmself_code"
SYM_STOP = b"__stop_vmself_code"


class Elf:
    def __init__(self, data):
        self.d = data
        if data[:4] != b"\x7fELF":
            raise ValueError("not ELF")
        self.is64 = data[4] == 2
        self.le = data[5] == 1
        self.e = "<" if self.le else ">"
        if self.is64:
            self.e_phoff = struct.unpack(self.e + "Q", data[0x20:0x28])[0]
            self.e_shoff = struct.unpack(self.e + "Q", data[0x28:0x30])[0]
            self.e_phentsize = struct.unpack(self.e + "H", data[0x36:0x38])[0]
            self.e_phnum = struct.unpack(self.e + "H", data[0x38:0x3A])[0]
            self.e_shentsize = struct.unpack(self.e + "H", data[0x3A:0x3C])[0]
            self.e_shnum = struct.unpack(self.e + "H", data[0x3C:0x3E])[0]
            self.e_shstrndx = struct.unpack(self.e + "H", data[0x3E:0x40])[0]
        else:
            self.e_phoff = struct.unpack(self.e + "I", data[0x1C:0x20])[0]
            self.e_shoff = struct.unpack(self.e + "I", data[0x20:0x24])[0]
            self.e_phentsize = struct.unpack(self.e + "H", data[0x2A:0x2C])[0]
            self.e_phnum = struct.unpack(self.e + "H", data[0x2C:0x2E])[0]
            self.e_shentsize = struct.unpack(self.e + "H", data[0x2E:0x30])[0]
            self.e_shnum = struct.unpack(self.e + "H", data[0x30:0x32])[0]
            self.e_shstrndx = struct.unpack(self.e + "H", data[0x32:0x34])[0]

    def _u(self, fmt, off):
        return struct.unpack(self.e + fmt, self.d[off:off + struct.calcsize(self.e + fmt)])[0]

    def sections(self):
        """yield (name_idx, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize)"""
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            name = self._u("I", off)
            if self.is64:
                stype = self._u("I", off + 4)
                addr = self._u("Q", off + 16)
                offset = self._u("Q", off + 24)
                size = self._u("Q", off + 32)
                link = self._u("I", off + 40)
                entsize = self._u("Q", off + 56)
            else:
                stype = self._u("I", off + 4)
                addr = self._u("I", off + 12)
                offset = self._u("I", off + 16)
                size = self._u("I", off + 20)
                link = self._u("I", off + 24)
                entsize = self._u("I", off + 36)
            yield name, stype, addr, offset, size, link, entsize

    def shstrtab(self):
        for i, (name, stype, addr, off, size, link, ent) in enumerate(self.sections()):
            if i == self.e_shstrndx:
                return self.d[off:off + size]
        return b""

    def secname(self, idx, shstr):
        end = shstr.find(b"\x00", idx)
        return bytes(shstr[idx:end]) if end >= 0 else b""

    def find_section_by_name(self, name):
        shstr = self.shstrtab()
        for name_idx, stype, addr, off, size, link, ent in self.sections():
            if self.secname(name_idx, shstr) == name:
                return off, size
        return None

    def find_symtab(self):
        SHT_SYMTAB = 2
        for name_idx, stype, addr, off, size, link, ent in self.sections():
            if stype == SHT_SYMTAB:
                return off, size, link, ent
        return None

    def symbols(self):
        """yield (name_bytes, st_value)"""
        r = self.find_symtab()
        if r is None:
            return
        off, size, link, ent = r
        # strtab = section[link]
        strtab_off = strtab_size = None
        for i, (nm, st, ad, of, sz, lk, en) in enumerate(self.sections()):
            if i == link:
                strtab_off, strtab_size = of, sz
        if strtab_off is None:
            return
        strtab = self.d[strtab_off:strtab_off + strtab_size]
        n = size // ent
        for i in range(n):
            so = off + i * ent
            if self.is64:
                st_name = self._u("I", so)
                st_value = self._u("Q", so + 8)
            else:
                st_name = self._u("I", so)
                st_value = self._u("I", so + 4)
            end = strtab.find(b"\x00", st_name)
            nm = bytes(strtab[st_name:end]) if end >= 0 else b""
            yield nm, st_value

    def loads(self):
        """yield (p_type, p_offset, p_vaddr, p_filesz) for PT_LOAD"""
        PT_LOAD = 1
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            ptype = self._u("I", off)
            if ptype != PT_LOAD:
                continue
            if self.is64:
                p_offset = self._u("Q", off + 8)
                p_vaddr = self._u("Q", off + 16)
                p_filesz = self._u("Q", off + 32)
            else:
                p_offset = self._u("I", off + 4)
                p_vaddr = self._u("I", off + 8)
                p_filesz = self._u("I", off + 16)
            yield p_offset, p_vaddr, p_filesz

    def vaddr_to_offset(self, vaddr):
        for p_offset, p_vaddr, p_filesz in self.loads():
            if p_vaddr <= vaddr < p_vaddr + p_filesz:
                return p_offset + (vaddr - p_vaddr)
        return None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    so_path = sys.argv[1]
    with open(so_path, "rb") as f:
        data = bytearray(f.read())

    elf = Elf(data)

    # 1. 定位区段范围(符号优先,节名回退)
    start_off = stop_off = None
    syms = {nm: val for nm, val in elf.symbols() if nm in (SYM_START, SYM_STOP)}
    if SYM_START in syms and SYM_STOP in syms:
        s = elf.vaddr_to_offset(syms[SYM_START])
        e = elf.vaddr_to_offset(syms[SYM_STOP])
        if s is not None and e is not None and e > s:
            start_off, stop_off = s, e
            src = "symbols(__start_/__stop_vmself_code)"
    if start_off is None:
        sec = elf.find_section_by_name(SECTION_NAME)
        if sec is not None:
            start_off, stop_off = sec[0], sec[0] + sec[1]
            src = "section(vmself_code)"
    if start_off is None or stop_off <= start_off:
        # VM 引擎未被任何代码引用时被 --gc-sections 回收(如 t3/t4 尚未接线的
        # Android release)——此时无 dispatch 可保护,运行时占位符全 0 自动跳过,
        # 属正常情况,不失败。待 VM 代码真正链入后本步自动生效。
        print("提示: vmself_code 区段不在链(VM 引擎被 gc-sections 回收/未启用),"
              "跳过 CRC 写入(运行时自引用校验将保持关闭)")
        sys.exit(0)

    # 2. 计算 CRC-32/IEEE(与运行时 vm_crc32_ieee 同算法)
    region = bytes(data[start_off:stop_off])
    crc = zlib.crc32(region) & 0xFFFFFFFF
    crc_hex = f"{crc:08x}".encode("ascii")

    # 3. 定位锚点写入(幂等)
    anchor_off = data.find(ANCHOR)
    if anchor_off < 0:
        print("错误: 未找到 VMSREF01 占位锚点(vm_engine.c 占位符被优化掉?检查 volatile)")
        sys.exit(1)
    hex_off = anchor_off + len(ANCHOR)
    if hex_off + 8 > len(data):
        print("错误: 锚点位置越界")
        sys.exit(1)
    data[hex_off:hex_off + 8] = crc_hex

    with open(so_path, "wb") as f:
        f.write(data)

    print(f"vmself_code [{src}] off=0x{start_off:x}..0x{stop_off:x} "
          f"size={stop_off - start_off} CRC32={crc_hex.decode()} 已写入")


if __name__ == "__main__":
    main()
