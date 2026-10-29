#!/bin/bash
# Build an installable VPNClient-<version>.pkg.
#
#   scripts/build-pkg.sh [output-dir]      # default: ./dist, host architecture
#   UNIVERSAL=1 XRAY_X86_64=/path/to/xray-x86_64 scripts/build-pkg.sh
#
# The helper only trusts a root-owned bundle, so the app must be installed from
# this .pkg (payload is owned by root:wheel), never run from target/.
# Xray is taken from $XRAY_BIN (default: ~/Applications/Xray/xray).
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
    (cd "$ROOT" && cargo build --release --target "$t" --bin vpn-tun-helper)
    (cd "$ROOT/src-tauri" && cargo build --release --target "$t" --features tauri/custom-protocol)
  done
  mkdir -p "$STAGE/bin"
  lipo -create -output "$STAGE/bin/app" "$ROOT/src-tauri/target/aarch64-apple-darwin/release/vpn-desktop" "$ROOT/src-tauri/target/x86_64-apple-darwin/release/vpn-desktop"
  lipo -create -output "$STAGE/bin/helper" "$ROOT/target/aarch64-apple-darwin/release/vpn-tun-helper" "$ROOT/target/x86_64-apple-darwin/release/vpn-tun-helper"
  lipo -create -output "$STAGE/bin/xray" "$XRAY_BIN" "$XRAY_X86_64"
  APP_BIN="$STAGE/bin/app"; HELPER_BIN="$STAGE/bin/helper"; XRAY_OUT="$STAGE/bin/xray"
else
  (cd "$ROOT" && cargo build --release --bin vpn-tun-helper)
  (cd "$ROOT/src-tauri" && cargo build --release --features tauri/custom-protocol)
  APP_BIN="$ROOT/src-tauri/target/release/vpn-desktop"; HELPER_BIN="$ROOT/target/release/vpn-tun-helper"; XRAY_OUT="$XRAY_BIN"
fi

APP="$STAGE/root/Applications/VPNClient.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Helpers" "$OUT"
cp "$APP_BIN" "$APP/Contents/MacOS/VPNClient"
cp "$HELPER_BIN" "$APP/Contents/Helpers/vpn-tun-helper"
cp "$XRAY_OUT" "$APP/Contents/Helpers/xray"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>VPNClient</string>
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

codesign --force --sign - "$APP/Contents/Helpers/xray" "$APP/Contents/Helpers/vpn-tun-helper"
codesign --force --sign - "$APP"

PKG="$OUT/VPNClient-$VERSION.pkg"
pkgbuild --root "$STAGE/root" --identifier local.vpn-client --version "$VERSION" \
  --install-location / --ownership recommended "$PKG"
echo "== $PKG"
shasum -a 256 "$PKG"
