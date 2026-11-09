#!/bin/bash
# Build an installable VPNClient-<version>.pkg.
#
#   scripts/build-pkg.sh [output-dir]      # default: ./dist, host architecture
#   TARGET=x86_64-apple-darwin XRAY_BIN=/path/to/xray scripts/build-pkg.sh
#   UNIVERSAL=1 XRAY_X86_64=/path/to/xray-x86_64 scripts/build-pkg.sh
#
# The helper only trusts a root-owned bundle, so the app must be installed from
# this .pkg (payload is owned by root:wheel), never run from target/.
# Xray is taken from $XRAY_BIN (default: ~/Applications/Xray/xray).
# GEO_DIR=/dir/with/geoip.dat+geosite.dat adds the databases that geoip:/geosite: exclusions need.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist}"
XRAY_BIN="${XRAY_BIN:-$HOME/Applications/Xray/xray}"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/src-tauri/Cargo.toml" | head -1)"
[ -n "$VERSION" ] || { echo "cannot read version from src-tauri/Cargo.toml" >&2; exit 1; }
[ -x "$XRAY_BIN" ] || { echo "xray not found: $XRAY_BIN (set XRAY_BIN)" >&2; exit 1; }

echo "== building $VERSION"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
if [ "${UNIVERSAL:-0}" = 1 ]; then
  [ -x "${XRAY_X86_64:-}" ] || { echo "UNIVERSAL=1 needs XRAY_X86_64" >&2; exit 1; }
  for t in aarch64-apple-darwin x86_64-apple-darwin; do
    (cd "$ROOT" && cargo build --release --target "$t" --bin vpn-tun-helper --bin vpn-core)
    (cd "$ROOT/src-tauri" && cargo build --release --target "$t" --features tauri/custom-protocol)
  done
  mkdir -p "$STAGE/bin"
  lipo -create -output "$STAGE/bin/app" "$ROOT/src-tauri/target/aarch64-apple-darwin/release/vpn-desktop" "$ROOT/src-tauri/target/x86_64-apple-darwin/release/vpn-desktop"
  lipo -create -output "$STAGE/bin/helper" "$ROOT/target/aarch64-apple-darwin/release/vpn-tun-helper" "$ROOT/target/x86_64-apple-darwin/release/vpn-tun-helper"
  lipo -create -output "$STAGE/bin/mcp" "$ROOT/target/aarch64-apple-darwin/release/vpn-core" "$ROOT/target/x86_64-apple-darwin/release/vpn-core"
  lipo -create -output "$STAGE/bin/xray" "$XRAY_BIN" "$XRAY_X86_64"
  APP_BIN="$STAGE/bin/app"; HELPER_BIN="$STAGE/bin/helper"; MCP_BIN="$STAGE/bin/mcp"; XRAY_OUT="$STAGE/bin/xray"
else
  TARGET="${TARGET:-}"
  TARGET_ARGS=(); [ -z "$TARGET" ] || TARGET_ARGS=(--target "$TARGET")
  (cd "$ROOT" && cargo build --release "${TARGET_ARGS[@]}" --bin vpn-tun-helper --bin vpn-core)
  (cd "$ROOT/src-tauri" && cargo build --release "${TARGET_ARGS[@]}" --features tauri/custom-protocol)
  TARGET_DIR="${TARGET:+$TARGET/}"
  APP_BIN="$ROOT/src-tauri/target/${TARGET_DIR}release/vpn-desktop"; HELPER_BIN="$ROOT/target/${TARGET_DIR}release/vpn-tun-helper"; MCP_BIN="$ROOT/target/${TARGET_DIR}release/vpn-core"; XRAY_OUT="$XRAY_BIN"
fi

APP="$STAGE/root/Applications/VPNClient.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Helpers" "$OUT"
cp "$APP_BIN" "$APP/Contents/MacOS/VPNClient"
cp "$HELPER_BIN" "$APP/Contents/Helpers/vpn-tun-helper"
cp "$MCP_BIN" "$APP/Contents/Helpers/vpn-mcp"
cp "$XRAY_OUT" "$APP/Contents/Helpers/xray"
mkdir -p "$APP/Contents/Resources"
cp "$ROOT/assets/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
# Domain/IP lists for geosite:/geoip: exclusions (from the official Xray release archive).
if [ -n "${GEO_DIR:-}" ]; then
  mkdir -p "$APP/Contents/Resources"
  cp "$GEO_DIR/geoip.dat" "$GEO_DIR/geosite.dat" "$APP/Contents/Resources/"
fi

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>VPNClient</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>CFBundleIdentifier</key>
	<string>local.vpn-client.app</string>
	<key>CFBundleName</key>
	<string>VPN Client</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>$VERSION</string>
	<key>CFBundleVersion</key>
	<string>$VERSION</string>
	<key>LSMinimumSystemVersion</key>
	<string>12.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
EOF

codesign --force --sign - "$APP/Contents/Helpers/xray" "$APP/Contents/Helpers/vpn-tun-helper" "$APP/Contents/Helpers/vpn-mcp"
codesign --force --sign - "$APP"

PKG="$OUT/VPNClient-$VERSION.pkg"
pkgbuild --root "$STAGE/root" --identifier local.vpn-client --version "$VERSION" \
  --install-location / --ownership recommended "$PKG"
echo "== $PKG"
shasum -a 256 "$PKG"
