#!/bin/bash
# Cross-builds the Windows client (import + connect only) on macOS and zips it.
# Needs: rustup target x86_64-pc-windows-gnu, `brew install mingw-w64`.
# Xray and wintun are downloaded once into dist/.win (override with XRAY_ZIP / WINTUN_ZIP).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET=x86_64-pc-windows-gnu
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
CACHE="$ROOT/dist/.win"; mkdir -p "$CACHE"
XRAY_ZIP="${XRAY_ZIP:-$CACHE/xray.zip}"; WINTUN_ZIP="${WINTUN_ZIP:-$CACHE/wintun.zip}"
[ -f "$XRAY_ZIP" ] || curl -fsSL -o "$XRAY_ZIP" https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip
[ -f "$WINTUN_ZIP" ] || curl -fsSL -o "$WINTUN_ZIP" https://www.wintun.net/builds/wintun-0.14.1.zip

touch "$ROOT/src-tauri/src/main.rs"
(cd "$ROOT" && cargo build --release --manifest-path src-tauri/Cargo.toml --target "$TARGET" --features tauri/custom-protocol)

NAME="VPNClient-Windows-$VERSION"; STAGE="$ROOT/dist/$NAME"
rm -rf "$STAGE" "$CACHE/x" "$CACHE/w"; mkdir -p "$STAGE/bin" "$STAGE/resources" "$CACHE/x" "$CACHE/w"
unzip -q "$XRAY_ZIP" -d "$CACHE/x"; unzip -q "$WINTUN_ZIP" -d "$CACHE/w"
cp "$ROOT/src-tauri/target/$TARGET/release/vpn-desktop.exe" "$STAGE/VPNClient.exe"
# The gnu build loads the WebView2 loader dynamically; it must sit next to the exe.
cp "$ROOT/src-tauri/target/$TARGET/release/WebView2Loader.dll" "$STAGE/WebView2Loader.dll"
cp "$CACHE/x/xray.exe" "$STAGE/bin/vpnclient-xray.exe"
cp "$CACHE/w/wintun/bin/amd64/wintun.dll" "$STAGE/bin/wintun.dll"
cp "$CACHE/x/geoip.dat" "$CACHE/x/geosite.dat" "$STAGE/resources/"
cp "$CACHE/x/LICENSE" "$STAGE/bin/LICENSE-Xray"; cp "$CACHE/w/wintun/LICENSE.txt" "$STAGE/bin/LICENSE-Wintun.txt" 2>/dev/null || cp "$CACHE/w/wintun/LICENSE-Wintun" "$STAGE/bin/LICENSE-Wintun.txt" 2>/dev/null || true
cat > "$STAGE/README.txt" <<TXT
VPN Client для Windows $VERSION

Запуск: VPNClient.exe (Windows спросит права администратора: они нужны, чтобы создать TUN-адаптер).
Подключение: «Импорт» -> вставьте ссылку vless:// или hysteria2:// -> выберите конфигурацию -> «Подключить».
Не переносите VPNClient.exe отдельно: рядом должны лежать папки bin и resources.
Требуется Windows 10/11 x64 и Microsoft Edge WebView2 (есть в Windows 11 и в обновлённой Windows 10).
TXT
(cd "$ROOT/dist" && rm -f "$NAME.zip" && zip -qr "$NAME.zip" "$NAME")

# Installer (needs `brew install makensis`).
SETUP="$ROOT/dist/VPNClient-Setup-$VERSION.exe"
makensis -V2 -DVERSION="$VERSION" -DSTAGE="$STAGE" -DOUT="$SETUP" -DICON="$ROOT/src-tauri/icons/icon.ico" "$ROOT/scripts/installer.nsi"
echo "== $SETUP"; shasum -a 256 "$SETUP"
echo "== $ROOT/dist/$NAME.zip"; shasum -a 256 "$ROOT/dist/$NAME.zip"
