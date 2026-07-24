#!/usr/bin/env python3
"""
patch_apk_hash.py - post-build 写入 APK 受保护内容真实 hash(方案 A v2.1.1)

计算 APK 受保护内容的真实 SHA-256(排除 defender .so 条目,解决鸡生蛋问题),
写入 hash_storage 的 8 段 XOR 编码占位符。

两种模式:
  --in-apk(推荐):直接在已签名 APK 内 patch .so + 更新 CRC-32 + 重签名
      python patch_apk_hash.py --in-apk <demo.apk> [--ks <keystore> --ks-pass <pass>]
  --aar:写入 .so 后重打包 .aar(需后续重建 APK,hash 会因构建差异不匹配)
      python patch_apk_hash.py <libxcj_defender.so> <demo.apk> <xcj-defender-sdk-release.aar>
"""
import os
import sys
import struct
import hashlib
import zipfile
import tempfile
import zlib
import subprocess
import shutil

OBF_KEY = 0x5A5A5A5A
CHUNK_SIZE = 1 << 20  # 1MB
SO_NAME = "libxcj_defender.so"
TEXT_CRC_PLACEHOLDER = 0x5AC05AC0
TEXT_OFF_PLACEHOLDER = 0x5AC05AC1
TEXT_SIZE_PLACEHOLDER = 0x5AC05AC2


# ============= .text CRC patch(方案 B) =============

def find_text_section(so_data: bytes):
    """解析 ELF section headers 找 .text 段的 vaddr 和大小"""
    if so_data[:4] != b'\x7fELF':
        return None, None

    is_64 = so_data[4] == 2
    if is_64:
        e_shoff = struct.unpack('<Q', so_data[40:48])[0]
        e_shentsize = struct.unpack('<H', so_data[58:60])[0]
        e_shnum = struct.unpack('<H', so_data[60:62])[0]
        e_shstrndx = struct.unpack('<H', so_data[62:64])[0]
    else:
        e_shoff = struct.unpack('<I', so_data[32:36])[0]
        e_shentsize = struct.unpack('<H', so_data[46:48])[0]
        e_shnum = struct.unpack('<H', so_data[48:50])[0]
        e_shstrndx = struct.unpack('<H', so_data[50:52])[0]

    if e_shoff == 0 or e_shnum == 0:
        return None, None

    # 读 section name string table
    shstr_off = e_shoff + e_shstrndx * e_shentsize
    if is_64:
        str_offset = struct.unpack('<Q', so_data[shstr_off + 24:shstr_off + 32])[0]
        str_size = struct.unpack('<Q', so_data[shstr_off + 32:shstr_off + 40])[0]
    else:
        str_offset = struct.unpack('<I', so_data[shstr_off + 16:shstr_off + 20])[0]
        str_size = struct.unpack('<I', so_data[shstr_off + 20:shstr_off + 24])[0]
    strtab = so_data[str_offset:str_offset + str_size]

    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack('<I', so_data[sh:sh + 4])[0]
        if is_64:
            sh_addr = struct.unpack('<Q', so_data[sh + 16:sh + 24])[0]
            sh_size = struct.unpack('<Q', so_data[sh + 32:sh + 40])[0]
        else:
            sh_addr = struct.unpack('<I', so_data[sh + 12:sh + 16])[0]
            sh_size = struct.unpack('<I', so_data[sh + 20:sh + 24])[0]

        name_end = strtab.find(b'\x00', sh_name_idx)
        name = strtab[sh_name_idx:name_end].decode('utf-8', errors='replace')

        if name == '.text':
            return sh_addr, sh_size

    return None, None


def patch_text_crc(so_data: bytearray) -> bool:
    """计算 .text CRC32 并写入 EMBEDDED_TEXT_INFO(CRC + 偏移 + 大小)"""
    text_vaddr, text_size = find_text_section(bytes(so_data))
    if text_vaddr is None:
        return False

    # .text 在文件中的偏移:对于第一个 PT_LOAD(vaddr=0),file_offset == vaddr
    # 计算 CRC
    text_crc = zlib.crc32(bytes(so_data[text_vaddr:text_vaddr + text_size])) & 0xFFFFFFFF

    # 找 3 个占位符
    crc_ph = struct.pack('<I', TEXT_CRC_PLACEHOLDER)
    off_ph = struct.pack('<I', TEXT_OFF_PLACEHOLDER)
    size_ph = struct.pack('<I', TEXT_SIZE_PLACEHOLDER)

    crc_idx = so_data.find(crc_ph)
    off_idx = so_data.find(off_ph)
    size_idx = so_data.find(size_ph)

    if crc_idx < 0 or off_idx < 0 or size_idx < 0:
        return False  # 已被 patch 或不存在

    so_data[crc_idx:crc_idx + 4] = struct.pack('<I', text_crc)
    so_data[off_idx:off_idx + 4] = struct.pack('<I', text_vaddr)
    so_data[size_idx:size_idx + 4] = struct.pack('<I', text_size)
    return True


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_segment_digest(data: bytes, seg_offset: int, seg_size: int,
                           patch_offset: int = -1, patch_value: int = 0) -> bytes:
    """计算一个区段的 1MB 分块 Merkle digest"""
    if seg_size == 0:
        return sha256(bytes([0x5a, 0, 0, 0, 0]))

    chunk_count = (seg_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    buf = bytes([0x5a]) + struct.pack('<I', chunk_count)

    pos = seg_offset
    for i in range(chunk_count):
        chunk_len = min(CHUNK_SIZE, seg_offset + seg_size - pos)
        chunk = bytearray(data[pos:pos + chunk_len])

        if patch_offset >= 0 and pos <= patch_offset < pos + chunk_len:
            off_in_chunk = patch_offset - pos
            chunk[off_in_chunk:off_in_chunk + 4] = struct.pack('<I', patch_value)

        chunk_buf = bytes([0xa5]) + struct.pack('<I', chunk_len) + bytes(chunk)
        buf += sha256(chunk_buf)
        pos += chunk_len

    return sha256(buf)


def find_so_exclude_ranges(data: bytes, cd_offset: int, cd_size: int):
    """在 Central Directory 中查找 defender .so 条目,返回需排除的范围"""
    ranges = []
    pos = cd_offset
    cd_end = cd_offset + cd_size

    while pos + 46 <= cd_end:
        if data[pos:pos + 4] != b'\x50\x4b\x01\x02':
            break

        fn_len = struct.unpack('<H', data[pos + 28:pos + 30])[0]
        ef_len = struct.unpack('<H', data[pos + 30:pos + 32])[0]
        fc_len = struct.unpack('<H', data[pos + 32:pos + 34])[0]
        comp_size = struct.unpack('<I', data[pos + 20:pos + 24])[0]
        local_offset = struct.unpack('<I', data[pos + 42:pos + 46])[0]

        if fn_len > 0 and pos + 46 + fn_len <= cd_end:
            fn = data[pos + 46:pos + 46 + fn_len].decode('utf-8', errors='replace')
            if fn.startswith('lib/') and SO_NAME in fn:
                cd_entry_size = 46 + fn_len + ef_len + fc_len
                ranges.append((pos, cd_entry_size))

                if local_offset + 30 <= len(data) and local_offset < cd_offset:
                    lfn_len = struct.unpack('<H', data[local_offset + 26:local_offset + 28])[0]
                    lef_len = struct.unpack('<H', data[local_offset + 28:local_offset + 30])[0]
                    local_entry_size = 30 + lfn_len + lef_len + comp_size
                    ranges.append((local_offset, local_entry_size))

        pos += 46 + fn_len + ef_len + fc_len

    return ranges


def apply_exclusions(buf: bytearray, buf_offset: int, buf_size: int, ranges):
    """将排除范围在缓冲区中置零"""
    for r_offset, r_size in ranges:
        r_start = r_offset
        r_end = r_offset + r_size
        b_start = buf_offset
        b_end = buf_offset + buf_size
        if r_start < b_end and r_end > b_start:
            z_start = max(r_start, b_start) - b_start
            z_end = min(r_end, b_end) - b_start
            buf[z_start:z_end] = b'\x00' * (z_end - z_start)


def compute_apk_protected_hash(apk_data: bytes) -> bytes:
    """计算 APK 受保护内容 SHA-256(4 区段,排除 defender .so)"""
    size = len(apk_data)

    eocd = -1
    for i in range(size - 22, 0, -1):
        if apk_data[i:i + 4] == b'\x50\x4b\x05\x06':
            eocd = i
            break
    if eocd < 0:
        raise ValueError("EOCD not found")

    cd_offset = struct.unpack('<I', apk_data[eocd + 16:eocd + 20])[0]

    footer_start = cd_offset - 24
    if apk_data[footer_start + 8:footer_start + 24] != b'APK Sig Block 42':
        raise ValueError("No APK Signing Block")
    block_size = struct.unpack('<Q', apk_data[footer_start:footer_start + 8])[0]
    block_start = cd_offset - 24 - block_size
    block_total = block_size + 24

    seg1_offset, seg1_size = 0, block_start
    seg3_offset = block_start + block_total
    seg3_size = eocd - seg3_offset
    seg4_offset, seg4_size = eocd, size - eocd

    ranges = find_so_exclude_ranges(apk_data, seg3_offset, seg3_size)
    if ranges:
        print(f"排除 defender .so 条目: {len(ranges)} 个范围")

    if ranges and seg1_size > 0:
        seg1_buf = bytearray(apk_data[seg1_offset:seg1_offset + seg1_size])
        apply_exclusions(seg1_buf, seg1_offset, seg1_size, ranges)
        digest1 = compute_segment_digest(bytes(seg1_buf), 0, seg1_size)
    else:
        digest1 = compute_segment_digest(apk_data, seg1_offset, seg1_size)

    if ranges and seg3_size > 0:
        seg3_buf = bytearray(apk_data[seg3_offset:seg3_offset + seg3_size])
        apply_exclusions(seg3_buf, seg3_offset, seg3_size, ranges)
        digest3 = compute_segment_digest(bytes(seg3_buf), 0, seg3_size)
    else:
        digest3 = compute_segment_digest(apk_data, seg3_offset, seg3_size)

    digest4 = compute_segment_digest(apk_data, seg4_offset, seg4_size,
                                      eocd + 16, block_start)

    return sha256(digest1 + digest3 + digest4)


# ============= .so 占位符 patch =============

def find_placeholder_positions(so_data: bytes):
    """在 .so 数据中找 8 个占位段的偏移"""
    placeholders = [struct.pack('<I', i ^ OBF_KEY) for i in range(8)]
    positions = []
    for ph in placeholders:
        idx = so_data.find(ph)
        if idx < 0:
            return None
        positions.append(idx)
    positions.sort()
    return positions


def patch_so_bytes(so_data: bytearray, apk_hash: bytes, positions):
    """在 .so 字节中写入 XOR 编码的真实 hash"""
    for i in range(8):
        seg = struct.unpack('<I', apk_hash[i * 4:(i + 1) * 4])[0]
        encoded = seg ^ OBF_KEY
        pos = positions[i]
        so_data[pos:pos + 4] = struct.pack('<I', encoded)


def patch_so_hash(so_path: str, apk_hash: bytes) -> None:
    """在 .so 文件中找 8 个占位段,写入 XOR 编码的真实 hash"""
    with open(so_path, 'rb') as f:
        data = bytearray(f.read())

    if data[:4] != b'\x7fELF':
        print(f"错误: {so_path} 不是 ELF")
        sys.exit(1)

    positions = find_placeholder_positions(bytes(data))
    if positions is None:
        print(f"错误: .so 中找不到完整占位段")
        sys.exit(1)

    print(f"找到 8 个占位段")
    print(f"APK hash: {apk_hash.hex()}")
    patch_so_bytes(data, apk_hash, positions)

    for i in range(8):
        seg = struct.unpack('<I', apk_hash[i * 4:(i + 1) * 4])[0]
        encoded = seg ^ OBF_KEY
        print(f"  段 {i + 1}: offset=0x{positions[i]:x} decoded=0x{seg:08x} encoded=0x{encoded:08x}")

    with open(so_path, 'wb') as f:
        f.write(data)
    print(f"已写入真实 APK hash 到 {so_path}")


# ============= in-place APK patch =============

def find_so_entries_in_apk(apk_data: bytes):
    """在 APK 中找 defender .so 的 ZIP 条目信息"""
    size = len(apk_data)

    # 找 EOCD
    eocd = -1
    for i in range(size - 22, 0, -1):
        if apk_data[i:i + 4] == b'\x50\x4b\x05\x06':
            eocd = i
            break
    if eocd < 0:
        raise ValueError("EOCD not found")

    cd_offset = struct.unpack('<I', apk_data[eocd + 16:eocd + 20])[0]
    cd_count = struct.unpack('<H', apk_data[eocd + 10:eocd + 12])[0]

    entries = []
    pos = cd_offset
    for _ in range(cd_count):
        if pos + 46 > size or apk_data[pos:pos + 4] != b'\x50\x4b\x01\x02':
            break

        fn_len = struct.unpack('<H', apk_data[pos + 28:pos + 30])[0]
        ef_len = struct.unpack('<H', apk_data[pos + 30:pos + 32])[0]
        fc_len = struct.unpack('<H', apk_data[pos + 32:pos + 34])[0]
        comp_size = struct.unpack('<I', apk_data[pos + 20:pos + 24])[0]
        uncomp_size = struct.unpack('<I', apk_data[pos + 24:pos + 28])[0]
        local_offset = struct.unpack('<I', apk_data[pos + 42:pos + 46])[0]
        crc32_val = struct.unpack('<I', apk_data[pos + 16:pos + 20])[0]

        fn = apk_data[pos + 46:pos + 46 + fn_len].decode('utf-8', errors='replace')

        if fn.startswith('lib/') and SO_NAME in fn:
            # 读 local file header
            lfn_len = struct.unpack('<H', apk_data[local_offset + 26:local_offset + 28])[0]
            lef_len = struct.unpack('<H', apk_data[local_offset + 28:local_offset + 30])[0]
            file_data_offset = local_offset + 30 + lfn_len + lef_len

            entries.append({
                'filename': fn,
                'cd_offset': pos,
                'cd_size': 46 + fn_len + ef_len + fc_len,
                'local_offset': local_offset,
                'file_data_offset': file_data_offset,
                'comp_size': comp_size,
                'uncomp_size': uncomp_size,
                'crc32': crc32_val,
            })

        pos += 46 + fn_len + ef_len + fc_len

    return entries


def find_hash_positions(so_data: bytes, target_hash: bytes):
    """在 .so 数据中找 target_hash 的 8 段 XOR 编码值位置"""
    positions = []
    for i in range(8):
        seg = struct.unpack('<I', target_hash[i * 4:(i + 1) * 4])[0]
        encoded = struct.pack('<I', seg ^ OBF_KEY)
        idx = so_data.find(encoded)
        if idx < 0:
            return None
        positions.append(idx)
    positions.sort()
    return positions


def patch_and_resign(apk_path: str, new_hash: bytes, old_hash: bytes,
                      ks_path: str, ks_pass: str, pass_num: int) -> bool:
    """在 APK 内 patch .so(占位符或旧 hash → 新 hash)+ 更新 CRC-32 + 重签名"""
    with open(apk_path, 'rb') as f:
        apk_data = bytearray(f.read())

    entries = find_so_entries_in_apk(bytes(apk_data))
    if not entries:
        print("错误: APK 中找不到 defender .so 条目")
        return False

    apksigner = find_apksigner()
    if apksigner is None:
        print("错误: 找不到 apksigner")
        return False

    for entry in entries:
        data_off = entry['file_data_offset']
        comp_size = entry['comp_size']
        so_data = bytearray(apk_data[data_off:data_off + comp_size])

        # 先找占位符,再找旧 hash 编码值
        positions = find_placeholder_positions(bytes(so_data))
        if positions is None and old_hash is not None:
            positions = find_hash_positions(bytes(so_data), old_hash)
        if positions is None:
            print(f"  Pass {pass_num} {entry['filename']}: 无法定位 hash 段,跳过")
            continue

        patch_so_bytes(so_data, new_hash, positions)

        # Pass 1 同时写入 .text CRC(方案 B)
        if pass_num == 1:
            if patch_text_crc(so_data):
                print(f"  Pass {pass_num} {entry['filename']}: .text CRC 已写入")

        apk_data[data_off:data_off + comp_size] = so_data

        new_crc32 = zlib.crc32(bytes(so_data)) & 0xFFFFFFFF
        apk_data[entry['local_offset'] + 14:entry['local_offset'] + 18] = struct.pack('<I', new_crc32)
        apk_data[entry['cd_offset'] + 16:entry['cd_offset'] + 20] = struct.pack('<I', new_crc32)
        print(f"  Pass {pass_num} {entry['filename']}: patched CRC=0x{new_crc32:08x}")

    unsigned_path = apk_path.replace('.apk', '-unsigned.apk')
    with open(unsigned_path, 'wb') as f:
        f.write(apk_data)

    # V1 禁用(与 Gradle minSdk>=24 一致),V2+V3 签名
    cmd = [apksigner, 'sign',
           '--ks', ks_path, '--ks-pass', f'pass:{ks_pass}',
           '--v1-signing-enabled', 'false',
           '--v2-signing-enabled', 'true',
           '--v3-signing-enabled', 'true',
           '--in', unsigned_path, '--out', apk_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"apksigner 失败: {result.stderr}")
        return False
    os.remove(unsigned_path)
    print(f"  Pass {pass_num} 重签名完成(V1 off, V2+V3 on)")
    return True


def inject_dex_crc(apk_path: str, ks_path: str, ks_pass: str):
    """Pass 0: 计算 DEX CRC32 并注入 defender-config.json"""
    import json as json_mod

    z = zipfile.ZipFile(apk_path, 'r')
    crc_entries = []
    for name in sorted(z.namelist()):
        if name.endswith('.dex'):
            data = z.read(name)
            crc = zlib.crc32(data) & 0xFFFFFFFF
            crc_entries.append(f"{name}:{crc:08x}")
            print(f"  DEX CRC: {name} = {crc:08x}")
    z.close()

    if not crc_entries:
        print("  无 DEX 文件,跳过 CRC 注入")
        return

    # 读取并修改 config
    z = zipfile.ZipFile(apk_path, 'r')
    config_name = 'assets/defender-config.json'
    try:
        config_text = z.read(config_name).decode('utf-8')
    except KeyError:
        print("  无 defender-config.json,跳过 CRC 注入")
        z.close()
        return

    config = json_mod.loads(config_text)
    config['integrityCrcTable'] = crc_entries
    new_config = json_mod.dumps(config, indent=2, ensure_ascii=False)
    z.close()

    # 重写 APK(替换 config entry)
    import tempfile
    tmp_path = apk_path + '.tmp'
    z_in = zipfile.ZipFile(apk_path, 'r')
    z_out = zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED)
    for item in z_in.infolist():
        if item.filename == config_name:
            z_out.writestr(item, new_config.encode('utf-8'))
        else:
            z_out.writestr(item, z_in.read(item.filename))
    z_in.close()
    z_out.close()

    # 替换原文件 + 重签
    os.replace(tmp_path, apk_path)
    apksigner = find_apksigner()
    if apksigner:
        unsigned = apk_path + '-unsigned'
        os.rename(apk_path, unsigned)
        cmd = [apksigner, 'sign', '--ks', ks_path, '--ks-pass', f'pass:{ks_pass}',
               '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
               '--v3-signing-enabled', 'true', '--in', unsigned, '--out', apk_path]
        subprocess.run(cmd, capture_output=True, text=True)
        if os.path.exists(unsigned):
            os.remove(unsigned)

    print(f"  DEX CRC 注入完成: {len(crc_entries)} 个条目")


def patch_apk_inplace(apk_path: str, ks_path: str, ks_pass: str):
    """三轮 in-place patch:

    Pass 0: 注入 DEX CRC 到 config + 重签
    Pass 1: patch 占位符 → hash1, 重签名(V1 off)
    Pass 2: 基于重签后 APK 计算 hash2, patch hash1 → hash2, 重签名
    验证: 最终 APK hash == hash2
    """
    # Pass 0: DEX CRC 注入
    print("Pass 0: DEX CRC 注入...")
    inject_dex_crc(apk_path, ks_path, ks_pass)

    # Pass 1
    with open(apk_path, 'rb') as f:
        orig_data = f.read()
    hash1 = compute_apk_protected_hash(orig_data)
    print(f"Pass 1 hash: {hash1.hex()}")
    if not patch_and_resign(apk_path, hash1, None, ks_path, ks_pass, 1):
        sys.exit(1)

    # Pass 2
    with open(apk_path, 'rb') as f:
        pass1_data = f.read()
    hash2 = compute_apk_protected_hash(pass1_data)
    print(f"Pass 2 hash: {hash2.hex()}")
    if not patch_and_resign(apk_path, hash2, hash1, ks_path, ks_pass, 2):
        sys.exit(1)

    # 验证
    with open(apk_path, 'rb') as f:
        final_data = f.read()
    final_hash = compute_apk_protected_hash(final_data)
    print(f"\n最终 APK hash: {final_hash.hex()}")
    print(f"预埋 hash:     {hash2.hex()}")

    if final_hash == hash2:
        # 验证 .so 中包含 hash2
        entries = find_so_entries_in_apk(final_data)
        all_ok = True
        for entry in entries:
            so_data = final_data[entry['file_data_offset']:entry['file_data_offset'] + entry['comp_size']]
            if find_hash_positions(so_data, hash2):
                print(f"  {entry['filename']}: 包含正确 hash")
            else:
                print(f"  {entry['filename']}: hash 不正确!")
                all_ok = False
        if all_ok:
            print("哈希匹配!方案 A 校验就绪")
        else:
            print("hash 写入异常,需排查")
            sys.exit(1)
    else:
        print("哈希不匹配,需排查(Signing Block 大小可能不稳定)")
        sys.exit(1)


def find_apksigner():
    """查找 apksigner 路径"""
    sdk_dir = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if not sdk_dir:
        # 尝试默认路径
        default = os.path.expanduser('~') + '/AppData/Local/Android/Sdk'
        if os.path.exists(default):
            sdk_dir = default
    if sdk_dir:
        bt_dir = os.path.join(sdk_dir, 'build-tools')
        if os.path.exists(bt_dir):
            versions = sorted(os.listdir(bt_dir), reverse=True)
            for v in versions:
                apksigner = os.path.join(bt_dir, v, 'apksigner.bat')
                if os.path.exists(apksigner):
                    return apksigner
    # 尝试 PATH
    if shutil.which('apksigner'):
        return 'apksigner'
    return None


# ============= 主入口 =============

def main():
    if len(sys.argv) >= 2 and sys.argv[1] == '--in-apk':
        # in-place APK patch 模式(两轮:解决重签名改变 APK 结构问题)
        if len(sys.argv) < 3:
            print(f"用法: {sys.argv[0]} --in-apk <demo.apk> [--ks <keystore>] [--ks-pass <password>]")
            print(f"  默认 keystore: ~/.android/debug.keystore  密码: android")
            print(f"  流程: Pass1 patch占位符+重签 → Pass2 计算新hash+再patch+重签 → 验证")
            sys.exit(1)

        apk_path = sys.argv[2]
        ks_path = os.path.expanduser('~/.android/debug.keystore')
        ks_pass = 'android'

        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == '--ks' and i + 1 < len(sys.argv):
                ks_path = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == '--ks-pass' and i + 1 < len(sys.argv):
                ks_pass = sys.argv[i + 1]
                i += 2
            else:
                i += 1

        patch_apk_inplace(apk_path, ks_path, ks_pass)

    else:
        # .aar 模式(旧流程)
        if len(sys.argv) < 4:
            print(f"用法: {sys.argv[0]} <libxcj_defender.so> <demo.apk> <xcj-defender-sdk-release.aar>")
            print(f"  或: {sys.argv[0]} --in-apk <demo.apk> [--ks <keystore>] [--ks-pass <password>]")
            sys.exit(1)

        so_path = sys.argv[1]
        apk_path = sys.argv[2]
        aar_path = sys.argv[3]

        with open(apk_path, 'rb') as f:
            apk_data = f.read()

        apk_hash = compute_apk_protected_hash(apk_data)
        print(f"APK 受保护内容 SHA-256: {apk_hash.hex()}")

        patch_so_hash(so_path, apk_hash)

        print(f"\n重新打包 .aar: {aar_path}")
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(aar_path, 'r') as z:
                z.extractall(tmpdir)

            for abi in ['arm64-v8a', 'armeabi-v7a']:
                so_in_aar = os.path.join(tmpdir, f'jni/{abi}/libxcj_defender.so')
                if os.path.exists(so_in_aar):
                    patch_so_hash(so_in_aar, apk_hash)
                    print(f"  已写入 {abi}/libxcj_defender.so")

            with zipfile.ZipFile(aar_path, 'w', zipfile.ZIP_DEFLATED) as z:
                for root, dirs, files in os.walk(tmpdir):
                    for f in files:
                        file_path = os.path.join(root, f)
                        arcname = os.path.relpath(file_path, tmpdir)
                        z.write(file_path, arcname)

        print(f"已重新打包 .aar: {aar_path}")


if __name__ == '__main__':
    main()