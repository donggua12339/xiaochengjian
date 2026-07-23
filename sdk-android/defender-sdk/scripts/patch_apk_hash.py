#!/usr/bin/env python3
"""
patch_apk_hash.py - post-build 写入 APK 受保护内容真实 hash(方案 A v2.1.1)

编译 defender-sdk .so 后运行,计算 APK 受保护内容的真实 SHA-256,
写入 hash_storage.c 的 8 段 XOR 编码占位符,使运行时方案 A 校验真正生效。

流程:
    1. 用 ELF section headers 定位 .rodata 中的 8 个占位段(0x5A5A5A5A)
    2. 计算 APK 受保护内容 SHA-256(4 区段 Merkle,复用 hash_calculator.c 逻辑)
    3. 拆成 8 段 × 4 字节,XOR 0x5A5A5A5A 编码
    4. 写回 .so 的 .rodata 占位符

注意:需先计算 APK hash(需 demo APK 路径),再写入 .so。
应在 Packer 封装后运行(Packer 生成最终 APK,计算其 hash 写入 .so)。
"""
import sys
import struct
import hashlib

OBF_KEY = 0x5A5A5A5A
PLACEHOLDER = 0x5A5A5A5A  # 占位值(0 XOR 0x5A5A5A5A)
CHUNK_SIZE = 1 << 20  # 1MB


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_segment_digest(data: bytes, seg_offset: int, seg_size: int,
                           patch_offset: int = -1, patch_value: int = 0) -> bytes:
    """计算一个区段的 1MB 分块 Merkle digest(复用 hash_calculator.c 逻辑)"""
    if seg_size == 0:
        return sha256(bytes([0x5a, 0, 0, 0, 0]))

    chunk_count = (seg_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    buf = bytes([0x5a]) + struct.pack('<I', chunk_count)

    pos = seg_offset
    for i in range(chunk_count):
        chunk_len = min(CHUNK_SIZE, seg_offset + seg_size - pos)
        chunk = bytearray(data[pos:pos + chunk_len])

        # EOCD 偏移替换
        if patch_offset >= 0 and pos <= patch_offset < pos + chunk_len:
            off_in_chunk = patch_offset - pos
            chunk[off_in_chunk:off_in_chunk + 4] = struct.pack('<I', patch_value)

        chunk_buf = bytes([0xa5]) + struct.pack('<I', chunk_len) + bytes(chunk)
        buf += sha256(chunk_buf)
        pos += chunk_len

    return sha256(buf)


def compute_apk_protected_hash(apk_data: bytes) -> bytes:
    """计算 APK 受保护内容 SHA-256(4 区段,复用 hash_calculator.c 逻辑)"""
    size = len(apk_data)

    # 找 EOCD
    eocd = -1
    for i in range(size - 22, 0, -1):
        if apk_data[i:i+4] == b'\x50\x4b\x05\x06':
            eocd = i
            break
    if eocd < 0:
        raise ValueError("EOCD not found")

    cd_offset = struct.unpack('<I', apk_data[eocd+16:eocd+20])[0]

    # 定位 Signing Block
    footer_start = cd_offset - 24
    if apk_data[footer_start+8:footer_start+24] != b'APK Sig Block 42':
        raise ValueError("No APK Signing Block")
    block_size = struct.unpack('<Q', apk_data[footer_start:footer_start+8])[0]
    block_start = cd_offset - 24 - block_size
    block_total = block_size + 24

    # 区段 1: 0 到 block_start
    # 区段 3: block_start+block_total 到 eocd
    # 区段 4: eocd 到 size(EOCD 偏移替换为 block_start)
    digest1 = compute_segment_digest(apk_data, 0, block_start)
    digest3 = compute_segment_digest(apk_data, block_start + block_total, eocd - (block_start + block_total))
    digest4 = compute_segment_digest(apk_data, eocd, size - eocd,
                                      eocd + 16, block_start)

    return sha256(digest1 + digest3 + digest4)


def patch_so_hash(so_path: str, apk_hash: bytes) -> None:
    """在 .so 中找 8 个占位段,写入 XOR 编码的真实 hash"""
    with open(so_path, 'rb') as f:
        data = bytearray(f.read())

    if data[:4] != b'\x7fELF':
        print(f"错误: {so_path} 不是 ELF")
        sys.exit(1)

    # 在整个 .so 中找 8 个占位段(不同值,避免常量池合并)
    # 占位值 = i ^ 0x5A5A5A5A (i = 0..7)
    # 注:volatile 变量可能在 .data 或 .rodata,全文件搜更可靠
    placeholders = [struct.pack('<I', i ^ OBF_KEY) for i in range(8)]
    positions = []
    for ph in placeholders:
        idx = data.find(ph)
        if idx < 0:
            print(f"错误: .so 中找不到占位段 {ph.hex()}")
            sys.exit(1)
        positions.append(idx)

    positions.sort()
    print(f"找到 8 个占位段")
    print(f"APK hash: {apk_hash.hex()}")

    # 拆成 8 段 × 4 字节,XOR 编码后写入
    for i in range(8):
        seg = struct.unpack('<I', apk_hash[i*4:(i+1)*4])[0]
        encoded = seg ^ OBF_KEY
        abs_pos = positions[i]
        data[abs_pos:abs_pos+4] = struct.pack('<I', encoded)
        print(f"  段 {i+1}: offset=0x{abs_pos:x} decoded=0x{seg:08x} encoded=0x{encoded:08x}")

    with open(so_path, 'wb') as f:
        f.write(data)
    print(f"已写入真实 APK hash 到 {so_path}")


def main():
    if len(sys.argv) < 4:
        print(f"用法: {sys.argv[0]} <libxcj_defender.so> <demo.apk> <xcj-defender-sdk-release.aar>")
        print(f"  1. 计算 demo.apk 的受保护内容 hash")
        print(f"  2. 写入 .so 的 8 段占位符")
        print(f"  3. 重新打包 .aar(把修改后的 .so 打包进去)")
        sys.exit(1)

    so_path = sys.argv[1]
    apk_path = sys.argv[2]
    aar_path = sys.argv[3]

    with open(apk_path, 'rb') as f:
        apk_data = f.read()

    apk_hash = compute_apk_protected_hash(apk_data)
    print(f"APK 受保护内容 SHA-256: {apk_hash.hex()}")

    # 写入 .so(build/intermediates 的 .so)
    patch_so_hash(so_path, apk_hash)

    # 重新打包 .aar(把修改后的 .so 打包进去)
    print(f"\n重新打包 .aar: {aar_path}")
    import zipfile
    import shutil
    import tempfile

    # 解压 .aar
    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(aar_path, 'r') as z:
            z.extractall(tmpdir)

        # 复制修改后的 .so 到解压目录
        for abi in ['arm64-v8a', 'armeabi-v7a']:
            so_in_aar = os.path.join(tmpdir, f'jni/{abi}/libxcj_defender.so')
            if os.path.exists(so_in_aar):
                # 只对 arm64-v8a 写入 hash(armeabi-v7a 用相同 hash)
                patch_so_hash(so_in_aar, apk_hash)
                print(f"  已写入 {abi}/libxcj_defender.so")

        # 重新打包 .aar
        with zipfile.ZipFile(aar_path, 'w', zipfile.ZIP_DEFLATED) as z:
            for root, dirs, files in os.walk(tmpdir):
                for f in files:
                    file_path = os.path.join(root, f)
                    arcname = os.path.relpath(file_path, tmpdir)
                    z.write(file_path, arcname)

    print(f"已重新打包 .aar: {aar_path}")


if __name__ == '__main__':
    import os
    main()
