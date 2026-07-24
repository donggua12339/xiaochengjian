#!/usr/bin/env python3
"""
patch_x0.py - X0 完整集成:让方案 A/B/C 在"外壳加密入 asset"下也通过。

外壳 libxcj_defender.so 不在 lib/(已加密入 assets/xcj_payload.bin),故:
  - .text CRC(方案B)+ APK hash(方案A)须在【加密前】补丁进独立外壳 .so;
  - APK hash 计算须【排除载荷 asset】(否则改外壳→密文变→hash 变,不收敛);
  - 密文与占位载荷【同大小】,in-place 覆盖不破坏 zip 结构;
  - 两轮 in-place(同方案A,稳定 Signing Block)。

每轮:
  1. 计算 APK hash(排除 xcj_payload.bin)= H
  2. patch 独立外壳:.text CRC(仅 round1)+ hash_storage = H
  3. RC4 加密外壳(x0_key.h 的密钥)→ 载荷(大小 = len(so)+10)
  4. 用载荷覆盖 APK 内 xcj_payload.bin 字节(同大小)+ 更新 CRC + 重签(V1 off,V2+V3 on)

用法:
  python patch_x0.py --apk <demo.apk> --so <libxcj_defender.so> --key-hex <hex>
"""
import os
import sys
import struct
import zlib
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import patch_apk_hash as pah
import so_cipher

PAYLOAD_ASSET = "assets/xcj_payload.bin"


def _find_eocd_cd(data):
    size = len(data)
    eocd = -1
    for i in range(size - 22, 0, -1):
        if data[i:i + 4] == b'\x50\x4b\x05\x06':
            eocd = i
            break
    if eocd < 0:
        raise ValueError("EOCD not found")
    cd_offset = struct.unpack('<I', data[eocd + 16:eocd + 20])[0]
    cd_count = struct.unpack('<H', data[eocd + 10:eocd + 12])[0]
    return eocd, cd_offset, cd_count


def find_entry_ranges(data, cd_offset, cd_size, asset_name):
    """找指定 asset 条目的排除范围(local entry + cd entry)"""
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
            if fn == asset_name:
                ranges.append((pos, 46 + fn_len + ef_len + fc_len))
                if local_offset + 30 <= len(data) and local_offset < cd_offset:
                    lfn_len = struct.unpack('<H', data[local_offset + 26:local_offset + 28])[0]
                    lef_len = struct.unpack('<H', data[local_offset + 28:local_offset + 30])[0]
                    ranges.append((local_offset, 30 + lfn_len + lef_len + comp_size))
        pos += 46 + fn_len + ef_len + fc_len
    return ranges


def find_payload_data(data):
    """找 payload asset 的 file data 偏移 + 大小(用于 in-place 覆盖)"""
    eocd, cd_offset, cd_count = _find_eocd_cd(data)
    size = len(data)
    pos = cd_offset
    for _ in range(cd_count):
        if pos + 46 > size or data[pos:pos + 4] != b'\x50\x4b\x01\x02':
            break
        fn_len = struct.unpack('<H', data[pos + 28:pos + 30])[0]
        ef_len = struct.unpack('<H', data[pos + 30:pos + 32])[0]
        fc_len = struct.unpack('<H', data[pos + 32:pos + 34])[0]
        comp_size = struct.unpack('<I', data[pos + 20:pos + 24])[0]
        local_offset = struct.unpack('<I', data[pos + 42:pos + 46])[0]
        fn = data[pos + 46:pos + 46 + fn_len].decode('utf-8', errors='replace')
        if fn == PAYLOAD_ASSET:
            lfn_len = struct.unpack('<H', data[local_offset + 26:local_offset + 28])[0]
            lef_len = struct.unpack('<H', data[local_offset + 28:local_offset + 30])[0]
            return {'data_off': local_offset + 30 + lfn_len + lef_len,
                    'comp_size': comp_size, 'local_offset': local_offset, 'cd_offset': pos}
        pos += 46 + fn_len + ef_len + fc_len
    return None


def compute_hash_excluding_payload(apk_data):
    """APK 受保护 hash,排除 payload asset(仿 pah.compute_apk_protected_hash,换排除目标)"""
    size = len(apk_data)
    eocd, cd_offset, _ = _find_eocd_cd(apk_data)
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

    ranges = find_entry_ranges(apk_data, seg3_offset, seg3_size, PAYLOAD_ASSET)
    if ranges:
        print(f"  排除载荷 asset 条目: {len(ranges)} 个范围")

    if ranges and seg1_size > 0:
        seg1_buf = bytearray(apk_data[seg1_offset:seg1_offset + seg1_size])
        pah.apply_exclusions(seg1_buf, seg1_offset, seg1_size, ranges)
        digest1 = pah.compute_segment_digest(bytes(seg1_buf), 0, seg1_size)
    else:
        digest1 = pah.compute_segment_digest(apk_data, seg1_offset, seg1_size)
    if ranges and seg3_size > 0:
        seg3_buf = bytearray(apk_data[seg3_offset:seg3_offset + seg3_size])
        pah.apply_exclusions(seg3_buf, seg3_offset, seg3_size, ranges)
        digest3 = pah.compute_segment_digest(bytes(seg3_buf), 0, seg3_size)
    else:
        digest3 = pah.compute_segment_digest(apk_data, seg3_offset, seg3_size)
    digest4 = pah.compute_segment_digest(apk_data, seg4_offset, seg4_size, eocd + 16, block_start)
    return pah.sha256(digest1 + digest3 + digest4)


def resign(apk_path, ks_path, ks_pass):
    apksigner = pah.find_apksigner()
    unsigned = apk_path.replace('.apk', '-unsigned.apk')
    os.rename(apk_path, unsigned)
    cmd = [apksigner, 'sign', '--ks', ks_path, '--ks-pass', f'pass:{ks_pass}',
           '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
           '--v3-signing-enabled', 'true', '--in', unsigned, '--out', apk_path]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"apksigner 失败: {r.stderr}")
        sys.exit(1)
    if os.path.exists(unsigned):
        os.remove(unsigned)


def patch_x0(apk_path, so_path, key, ks_path, ks_pass):
    with open(so_path, 'rb') as f:
        so_data = bytearray(f.read())
    payload_size = len(so_data) + so_cipher.TRAILER_LEN

    prev_H = None
    for round_num in (1, 2):
        with open(apk_path, 'rb') as f:
            apk_data = bytearray(f.read())
        H = compute_hash_excluding_payload(bytes(apk_data))
        print(f"Round {round_num} hash(排除载荷): {H.hex()}")

        if round_num == 1:
            if pah.patch_text_crc(so_data):
                print(f"  Round {round_num}: .text CRC 已写入")
            positions = pah.find_placeholder_positions(bytes(so_data))
        else:
            positions = pah.find_hash_positions(bytes(so_data), prev_H)
        if positions is None:
            print(f"  Round {round_num}: 无法定位 hash 占位段")
            sys.exit(1)
        pah.patch_so_bytes(so_data, H, positions)
        prev_H = H

        framed = so_cipher.frame(bytes(so_data), key)
        if len(framed) != payload_size:
            print(f"  载荷大小变化 {len(framed)} != {payload_size}")
            sys.exit(1)

        info = find_payload_data(bytes(apk_data))
        if info is None:
            print("  APK 中找不到载荷 asset")
            sys.exit(1)
        if info['comp_size'] != payload_size:
            print(f"  asset 大小不符 {info['comp_size']} != {payload_size}(占位载荷须与密文同大小)")
            sys.exit(1)
        apk_data[info['data_off']:info['data_off'] + payload_size] = framed
        new_crc = zlib.crc32(framed) & 0xFFFFFFFF
        apk_data[info['local_offset'] + 14:info['local_offset'] + 18] = struct.pack('<I', new_crc)
        apk_data[info['cd_offset'] + 16:info['cd_offset'] + 20] = struct.pack('<I', new_crc)
        with open(apk_path, 'wb') as f:
            f.write(apk_data)
        resign(apk_path, ks_path, ks_pass)
        print(f"  Round {round_num}: 载荷已覆盖 + 重签")

    with open(apk_path, 'rb') as f:
        final = f.read()
    final_H = compute_hash_excluding_payload(final)
    print(f"\n最终 hash(排除载荷): {final_H.hex()}")
    print(f"预埋 hash:           {prev_H.hex()}")
    if final_H == prev_H:
        print("哈希匹配!方案 A 就绪(X0)")
    else:
        print("哈希不匹配,需排查(Signing Block 稳定性)")
        sys.exit(1)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="X0 完整集成:方案 A/B/C 适配外壳加密")
    ap.add_argument('--apk', required=True)
    ap.add_argument('--so', required=True, help='独立 libxcj_defender.so(已构建,含占位符)')
    ap.add_argument('--key-hex', required=True, help='RC4 密钥 hex(= x0_key.h 的密钥)')
    ap.add_argument('--ks', default=os.path.expanduser('~/.android/debug.keystore'))
    ap.add_argument('--ks-pass', default='android')
    args = ap.parse_args()

    print("Pass 0: DEX CRC 注入...")
    pah.inject_dex_crc(args.apk, args.ks, args.ks_pass)
    patch_x0(args.apk, args.so, bytes.fromhex(args.key_hex), args.ks, args.ks_pass)


if __name__ == '__main__':
    main()
