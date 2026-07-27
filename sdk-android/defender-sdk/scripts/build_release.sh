#!/usr/bin/env bash
# build_release.sh - 一键构建加固 APK(四步流水线)
#
# 用法: ./scripts/build_release.sh [--t4] [--install] [--key-hex HEX]
#
# 步骤:
#   1. defender-sdk assembleRelease (native 编译 + Hikari + X1 字符串变换)
#   2. build_x0_pack.py (RC4 加密 defender.so → xcj_payload.bin)
#   3. defender-demo assembleRelease (打包 demo APK)
#   4. patch_x0.py (两轮 in-place hash + 重签)
#   可选 5. encrypt-strings (T4 DEX 字符串加密,需 --t4)
#   可选 6. adb install (需 --install)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="$(dirname "$SCRIPT_DIR")"
ANDROID_DIR="$(dirname "$SDK_DIR")"
DEMO_DIR="$ANDROID_DIR/defender-demo"
INJECTOR_DIR="$(dirname "$ANDROID_DIR")/injector"

# 解析参数
DO_T4=false
DO_INSTALL=false
KEY_HEX=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --t4) DO_T4=true; shift ;;
        --install) DO_INSTALL=true; shift ;;
        --key-hex) KEY_HEX="$2"; shift 2 ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

SO_PATH="$SDK_DIR/build/intermediates/stripped_native_libs/release/stripReleaseDebugSymbols/out/lib/arm64-v8a/libxcj_defender.so"
APK_PATH="$DEMO_DIR/build/outputs/apk/release/defender-demo-release-unsigned.apk"

echo "=== 小城笺加固 APK 构建 ==="
echo ""

# Step 1: SDK
echo "[1/4] 构建 defender-sdk (assembleRelease)..."
cd "$SDK_DIR"
./gradlew assembleRelease -q 2>&1 | tail -3
echo "  ✓ SDK 构建完成"

# Step 2: X0 加密
echo "[2/4] X0 SO 加密 (build_x0_pack.py)..."
PACK_OUT=$(python "$SCRIPT_DIR/build_x0_pack.py" --so "$SO_PATH" 2>&1)
if [ -z "$KEY_HEX" ]; then
    KEY_HEX=$(echo "$PACK_OUT" | grep -oP '密钥\(hex\): \K[0-9a-f]+')
fi
echo "  ✓ 密钥: ${KEY_HEX:0:16}..."

# Step 3: Demo APK
echo "[3/4] 构建 defender-demo (assembleRelease)..."
cd "$DEMO_DIR"
./gradlew assembleRelease -q 2>&1 | tail -3
echo "  ✓ Demo APK 构建完成"

# Step 4: patch_x0
echo "[4/4] patch_x0 两轮 hash + 重签..."
cd "$SDK_DIR"
PATCH_OUT=$(python "$SCRIPT_DIR/patch_x0.py" --apk "$APK_PATH" --so "$SO_PATH" --key-hex "$KEY_HEX" 2>&1)
if echo "$PATCH_OUT" | grep -q "哈希匹配"; then
    echo "  ✓ 方案 A 哈希匹配"
else
    echo "  ✗ 哈希不匹配!"
    echo "$PATCH_OUT" | tail -5
    exit 1
fi

# 可选 Step 5: T4
if [ "$DO_T4" = true ]; then
    echo "[5] T4 DEX 字符串加密 (encrypt-strings)..."
    T4_APK="${APK_PATH%.apk}-t4.apk"
    cd "$INJECTOR_DIR"
    java -jar build/install/xcj-injector/lib/xcj-injector-all.jar \
        encrypt-strings --apk "$APK_PATH" --output "$T4_APK" \
        --key-header "$SDK_DIR/src/main/cpp/t4_str_key.h" 2>&1 | grep -E "加密|完成"
    # Re-patch on T4 APK
    cd "$SDK_DIR"
    python "$SCRIPT_DIR/patch_x0.py" --apk "$T4_APK" --so "$SO_PATH" --key-hex "$KEY_HEX" 2>&1 | grep "匹配"
    APK_PATH="$T4_APK"
    echo "  ✓ T4 加密完成"
fi

# 可选 Step 6: Install
if [ "$DO_INSTALL" = true ]; then
    echo "[*] 安装到设备..."
    adb install -r "$APK_PATH" 2>&1 | tail -1
    echo "  ✓ 安装完成"
fi

echo ""
echo "=== 构建完成 ==="
echo "APK: $APK_PATH"
echo "密钥: $KEY_HEX"
