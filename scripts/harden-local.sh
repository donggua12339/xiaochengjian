#!/usr/bin/env bash
# 本地加固脚本 —— 镜像后端 hardening.service 管线,在 Windows 本地产出可安装加固 APK。
# 后端用 execFile 驱动工具,但 Windows 下 execFile 跑不了 jar(apktool/apksigner),
# 故本脚本用 shell 直接调 java -jar / .exe,步骤与后端管线一致:
#   strip 签名 → apktool d(--no-src) → 改 Manifest → apktool b → 注入 config/dex/so
#   → T4 字符串加密 → zipalign → apksigner 重签
set -euo pipefail

# ===== 参数 =====
IN_APK="${1:?用法: harden-local.sh <input.apk> [output.apk]}"
OUT_APK="${2:-${IN_APK%.apk}-hardened.apk}"

# ===== 工具路径 =====
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/backend/tools-local"
BT="/c/Users/Admini/AppData/Local/Android/Sdk/build-tools/34.0.0"
ZIP="$TOOLS/zip.exe"
ZIPALIGN="$TOOLS/zipalign.exe"
APKTOOL() { java -jar "$TOOLS/apktool.jar" "$@"; }
APKSIGNER() { java -jar "$TOOLS/apksigner.jar" "$@"; }

# ===== Keystore(默认签名,来自 backend/.env) =====
KS_PATH="/d/Text_Box/Key/Keystore/donggua16600.jks"
KS_PASS="@YYM148075"
KS_ALIAS="donggua16600"
KEY_PASS="620753"

SDK="$ROOT/deploy/sdk-artifacts"
WORK="$(mktemp -d /tmp/harden-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

echo "==> 输入: $IN_APK"
echo "==> 输出: $OUT_APK"
echo "==> 工作目录: $WORK"
cp "$IN_APK" "$WORK/work.apk"
cd "$WORK"

# 随机 SO 伪装名(30 池风格)
SO_NAME="lib$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n').so"
echo "==> 随机 SO 名: $SO_NAME"

echo "==> [1] strip 旧签名 (zip -d META-INF/*)"
"$ZIP" -d work.apk 'META-INF/*' >/dev/null 2>&1 || true

echo "==> [2] apktool d --no-src (解码 Manifest,跳过 DEX 反编译)"
APKTOOL d -f --no-src -o decoded work.apk >/dev/null

echo "==> [3] 修改 AndroidManifest.xml"
MANIFEST="decoded/AndroidManifest.xml"
PKG=$(grep -oE 'package="[^"]+"' "$MANIFEST" | head -1 | sed 's/package="//;s/"//')
echo "    包名: $PKG"
# 若未注入,则在 <application ...> 后插入 meta-data + provider,并补 INTERNET 权限
if ! grep -q 'xcj.defender.lib' "$MANIFEST"; then
  python - "$MANIFEST" "$SO_NAME" "$PKG" <<'PY'
import sys
path, so_name, pkg = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path, encoding='utf-8').read()
meta = f'<meta-data android:name="xcj.defender.lib" android:value="{so_name}"/>'
provider = (f'<provider android:name="com.xcj.defender.DefenderInitProvider" '
            f'android:authorities="{pkg}.xcj.defender.init" android:exported="false" android:initOrder="100"/>')
i = s.find('<application')
i = s.find('>', i) + 1
s = s[:i] + '\n' + meta + '\n' + provider + s[i:]
if 'android.permission.INTERNET' not in s:
    j = s.find('<manifest')
    j = s.find('>', j) + 1
    s = s[:j] + '\n<uses-permission android:name="android.permission.INTERNET"/>' + s[j:]
open(path, 'w', encoding='utf-8').write(s)
print("    manifest 已注入 meta-data + provider + INTERNET")
PY
fi

echo "==> [4] apktool b (重建)"
APKTOOL b -o work.apk decoded >/dev/null
rm -rf decoded

echo "==> [5] 注入 defender-config.json / SDK dex / SO"
mkdir -p assets
cat > assets/defender-config.json <<JSON
{
  "version": 2,
  "appId": "$PKG",
  "serverUrl": "",
  "soName": "$SO_NAME",
  "killPolicy": { "strongEvidence": "kill" }
}
JSON
"$ZIP" -r work.apk assets/defender-config.json >/dev/null

# SDK dex → classes{N+1}.dex
NDEX=$(unzip -l work.apk | grep -oE 'classes[0-9]*\.dex' | sed 's/classes//;s/\.dex//' | sed 's/^$/1/' | sort -n | tail -1)
NEXT=$((NDEX + 1))
cp "$SDK/classes.dex" "classes$NEXT.dex"
"$ZIP" work.apk "classes$NEXT.dex" >/dev/null
echo "    注入 classes$NEXT.dex"

# SO(两 ABI,-0 存储保持对齐)
#  - defender SO → 随机名(Manifest meta-data xcj.defender.lib 指向它,DefenderNative.load 加载)
#  - loader  SO → 固定名 libxcj_loader.so(System.loadLibrary("xcj_loader") 需要,提供 XcjObfStr)
for ABI in arm64-v8a armeabi-v7a; do
  mkdir -p "lib/$ABI"
  if [ -f "$SDK/lib/$ABI/libxcj_defender.so" ]; then
    cp "$SDK/lib/$ABI/libxcj_defender.so" "lib/$ABI/$SO_NAME"
    "$ZIP" -0 work.apk "lib/$ABI/$SO_NAME" >/dev/null
    echo "    注入 lib/$ABI/$SO_NAME (defender,随机名)"
  fi
  if [ -f "$SDK/lib/$ABI/libxcj_loader.so" ]; then
    cp "$SDK/lib/$ABI/libxcj_loader.so" "lib/$ABI/libxcj_loader.so"
    "$ZIP" -0 work.apk "lib/$ABI/libxcj_loader.so" >/dev/null
    echo "    注入 lib/$ABI/libxcj_loader.so (loader,固定名)"
  fi
done

echo "==> [5.5] T4 DEX 字符串加密(业务代码 const-string → native 解密调用)"
INJECTOR_JAR="$ROOT/injector/build/install/xcj-injector/lib/xcj-injector-all.jar"
T4_KEY_HEADER="$ROOT/sdk-android/defender-sdk/src/main/cpp/t4_str_key.h"
if [ ! -f "$INJECTOR_JAR" ]; then
  echo "    !! injector jar 不存在,先跑: cd injector && ./gradlew installDist"
  exit 1
fi
# 密钥取自 t4_str_key.h(与预编译 defender SO 内的 T4_XOR_KEY 一致,运行时才能解密)
T4_KEY_HEX=$(grep -oE '0x[0-9a-fA-F]{2}' "$T4_KEY_HEADER" | sed 's/0x//' | tr -d '\n')
java -jar "$INJECTOR_JAR" encrypt-strings \
  --apk work.apk --output work-t4.apk \
  --key-hex "$T4_KEY_HEX" --key-header "$WORK/t4_key.h" 2>&1 | grep -E "注入|完成|保留" || true
mv work-t4.apk work.apk

echo "==> [6] zipalign -p -f 4"
"$ZIPALIGN" -p -f 4 work.apk aligned.apk
mv aligned.apk work.apk

echo "==> [7] apksigner sign (V1+V2+V3)"
APKSIGNER sign \
  --ks "$KS_PATH" --ks-pass "pass:$KS_PASS" \
  --ks-key-alias "$KS_ALIAS" --key-pass "pass:$KEY_PASS" \
  --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
  --in work.apk --out "$OUT_APK"

echo "==> [8] apksigner verify"
APKSIGNER verify --print-certs "$OUT_APK" | grep -E "Verified|Signer" | head -4

echo ""
echo "==> 完成: $OUT_APK"
ls -la "$OUT_APK"
echo "==> 产物内容核对:"
unzip -l "$OUT_APK" | grep -E "classes.*\.dex|libxcj|defender-config|AndroidManifest" | head -12
