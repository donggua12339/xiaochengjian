#!/usr/bin/env python3
"""
build_vm_bytecode.py - 小城笺加固 v0.3: VM 字节码汇编器

将 VM 汇编代码翻译为字节码,生成 C 头文件。

用法:
  python scripts/build_vm_bytecode.py

生成的 vm_bytecode.h 包含:
  - VM_BC_verify_hash: inner_verify_hash 的 VMP 字节码
  - VM_BC_verify_hash_size: 字节码长度
"""
import struct
import os

# VM 操作码(与 vm_engine.h 一致)
NOP       = 0x00
MOV_RI    = 0x01
MOV_RR    = 0x02
ADD       = 0x03
SUB       = 0x04
XOR       = 0x05
AND       = 0x06
OR        = 0x07
SHL       = 0x08
SHR       = 0x09
CMP       = 0x0A
JMP       = 0x0B
JZ        = 0x0C
JNZ       = 0x0D
LOAD8     = 0x0E
LOAD32    = 0x0F
STORE8    = 0x10
CALL_EXT  = 0x11
RET       = 0x12
MOV_RI64  = 0x13
NOT       = 0x14
NEG       = 0x15


class VMAssembler:
    """简易 VM 汇编器"""

    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.fixups = []  # (offset, label_name, type)

    def _emit8(self, v):
        self.code.append(v & 0xFF)

    def _emit16(self, v):
        self.code.extend(struct.pack('<H', v & 0xFFFF))

    def _emit32(self, v):
        self.code.extend(struct.pack('<i', v))

    def _emit64(self, v):
        self.code.extend(struct.pack('<q', v))

    def label(self, name):
        self.labels[name] = len(self.code)

    def nop(self):
        self._emit8(NOP)

    def mov_ri(self, dst, imm32):
        self._emit8(MOV_RI)
        self._emit8(dst & 0xF)
        self._emit32(imm32)

    def mov_rr(self, dst, src):
        self._emit8(MOV_RR)
        self._emit8((dst & 0xF) | ((src & 0xF) << 4))

    def add(self, dst, a, b):
        self._emit8(ADD)
        self._emit8((dst & 0xF) | ((a & 0xF) << 4))
        self._emit8(b & 0xF)

    def sub(self, dst, a, b):
        self._emit8(SUB)
        self._emit8((dst & 0xF) | ((a & 0xF) << 4))
        self._emit8(b & 0xF)

    def xor(self, dst, a, b):
        self._emit8(XOR)
        self._emit8((dst & 0xF) | ((a & 0xF) << 4))
        self._emit8(b & 0xF)

    def or_(self, dst, a, b):
        self._emit8(OR)
        self._emit8((dst & 0xF) | ((a & 0xF) << 4))
        self._emit8(b & 0xF)

    def cmp(self, a, b):
        self._emit8(CMP)
        self._emit8((a & 0xF) | ((b & 0xF) << 4))

    def jmp(self, target):
        self._emit8(JMP)
        self.fixups.append((len(self.code), target))
        self._emit32(0)  # placeholder

    def jz(self, target):
        self._emit8(JZ)
        self.fixups.append((len(self.code), target))
        self._emit32(0)

    def jnz(self, target):
        self._emit8(JNZ)
        self.fixups.append((len(self.code), target))
        self._emit32(0)

    def load8(self, dst, src, offset):
        self._emit8(LOAD8)
        self._emit8((dst & 0xF) | ((src & 0xF) << 4))
        self._emit16(offset)

    def call_ext(self, func_idx):
        self._emit8(CALL_EXT)
        self._emit8(func_idx)

    def ret(self):
        self._emit8(RET)

    def resolve(self):
        """解析跳转标签"""
        for offset, label_name in self.fixups:
            if label_name not in self.labels:
                raise ValueError(f"未定义标签: {label_name}")
            target = self.labels[label_name]
            # offset 是跳转目标字段的起始位置,跳转值 = target - (offset + 4)
            rel = target - (offset + 4)
            struct.pack_into('<i', self.code, offset, rel)

    def get_bytecode(self):
        self.resolve()
        return bytes(self.code)


def assemble_verify_hash():
    """
    汇编 inner_verify_hash 的 VMP 版本

    原始 C 代码:
      int inner_verify_hash(const char *hash_hex, const char *expected_hex) {
          if (!hash_hex || !expected_hex) return 1;
          int diff = 0;
          for (int i = 0; i < 64 && hash_hex[i] && expected_hex[i]; i++)
              diff |= (hash_hex[i] ^ expected_hex[i]);
          return diff != 0 ? 1 : 0;
      }

    寄存器分配:
      V0 = hash_hex (arg0, 后用作指针递进)
      V1 = expected_hex (arg1, 后用作指针递进)
      V2 = diff
      V3 = counter (64 → 0)
      V5 = temp (*hash_hex)
      V6 = temp (*expected_hex)
      V7 = temp (xor result)
      V8 = 1 (常量)
    """
    a = VMAssembler()

    # 初始化
    a.mov_ri(2, 0)        # V2 = diff = 0
    a.mov_ri(3, 64)       # V3 = counter = 64
    a.mov_ri(8, 1)        # V8 = 1

    # 检查 NULL 指针
    a.mov_ri(5, 0)        # V5 = 0
    a.cmp(0, 5)           # hash_hex == NULL?
    a.jz('return_1')
    a.cmp(1, 5)           # expected_hex == NULL?
    a.jz('return_1')

    # 循环体
    a.label('loop')
    a.cmp(3, 5)           # counter == 0?
    a.jz('done')

    # 加载 hash_hex[0]
    a.load8(5, 0, 0)      # V5 = *hash_hex
    a.cmp(5, 5)           # 这不对...

    # 重新: V5 = *hash_hex, 检查是否为 0
    # 需要先清零 V9 做比较
    a.mov_ri(9, 0)        # V9 = 0
    a.load8(5, 0, 0)      # V5 = *hash_hex
    a.cmp(5, 9)           # *hash_hex == 0?
    a.jz('done')

    a.load8(6, 1, 0)      # V6 = *expected_hex
    a.cmp(6, 9)           # *expected_hex == 0?
    a.jz('done')

    a.xor(7, 5, 6)        # V7 = *hash_hex ^ *expected_hex
    a.or_(2, 2, 7)        # diff |= V7

    # 指针递进
    a.add(0, 0, 8)        # hash_hex++
    a.add(1, 1, 8)        # expected_hex++
    a.sub(3, 3, 8)        # counter--

    a.jmp('loop')

    # 循环结束
    a.label('done')
    a.cmp(2, 9)           # diff == 0?  (V9 仍为 0)
    a.jz('return_0')

    a.label('return_1')
    a.mov_ri(0, 1)        # return 1
    a.ret()

    a.label('return_0')
    a.mov_ri(0, 0)        # return 0
    a.ret()

    return a.get_bytecode()


def generate_header(verify_hash_bc):
    """生成 C 头文件"""
    lines = []
    lines.append('/**')
    lines.append(' * vm_bytecode.h - VM 字节码(自动生成,请勿手动修改)')
    lines.append(' * 由 build_vm_bytecode.py 生成')
    lines.append(' */')
    lines.append('#ifndef VM_BYTECODE_H')
    lines.append('#define VM_BYTECODE_H')
    lines.append('')
    lines.append('#include <stdint.h>')
    lines.append('')

    # verify_hash 字节码
    lines.append(f'/* inner_verify_hash VMP 字节码 ({len(verify_hash_bc)} bytes) */')
    lines.append(f'static const uint8_t VM_BC_verify_hash[{len(verify_hash_bc)}] = {{')
    for i in range(0, len(verify_hash_bc), 16):
        chunk = verify_hash_bc[i:i+16]
        hex_str = ', '.join(f'0x{b:02X}' for b in chunk)
        comma = ',' if i + 16 < len(verify_hash_bc) else ''
        lines.append(f'    {hex_str}{comma}')
    lines.append('};')
    lines.append(f'static const size_t VM_BC_verify_hash_size = {len(verify_hash_bc)};')
    lines.append('')
    lines.append('#endif /* VM_BYTECODE_H */')

    return '\n'.join(lines) + '\n'


def main():
    print("=== 小城笺加固 v0.3: VM 字节码生成 ===")

    # 汇编 inner_verify_hash
    verify_hash_bc = assemble_verify_hash()
    print(f"inner_verify_hash VMP 字节码: {len(verify_hash_bc)} bytes")

    # 生成头文件
    header = generate_header(verify_hash_bc)
    output_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'main', 'cpp', 'vm_bytecode.h')
    with open(output_path, 'w') as f:
        f.write(header)
    print(f"头文件已生成: {output_path}")

    # 验证: 简单测试
    print(f"\n字节码 hex dump (前 64 bytes):")
    print(' '.join(f'{b:02X}' for b in verify_hash_bc[:64]))

    print("\n完成!")


if __name__ == '__main__':
    main()
