#!/bin/bash
# Builds a Debian package of the GPUI client (run on a Linux box).
# usage: scripts/build-linux-deb.sh [output-dir]   # default: ./dist
# Needs: cargo, dpkg-deb. The TUN helper is separate: sudo scripts/install-linux-helper.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist}"; OUT="${OUT%/}"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/gpui-client/Cargo.toml" | head -1)"
[ -n "$VERSION" ] || { echo "cannot read version from gpui-client/Cargo.toml" >&2; exit 1; }

echo "== building vpn-gpui $VERSION"
(cd "$ROOT/gpui-client" && cargo build --release)
BIN="$ROOT/gpui-client/target/release/vpn-gpui"
[ -x "$BIN" ] || { echo "build produced no binary" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/usr/share/applications" "$STAGE/usr/share/pixmaps" "$OUT"
install -m 755 "$BIN" "$STAGE/usr/bin/vpn-gpui"
install -m 644 "$ROOT/assets/icon-1024.png" "$STAGE/usr/share/pixmaps/vpn-client.png"
cat > "$STAGE/usr/share/applications/vpn-client.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=VPN Client
Comment=VPN Client (TUN)
Exec=/usr/bin/vpn-gpui
Icon=vpn-client
Terminal=false
Categories=Network;
StartupWMClass=vpn-gpui
EOF
cat > "$STAGE/DEBIAN/control" <<EOF
Package: vpn-client
Version: $VERSION
Architecture: amd64
Maintainer: VPN Client <jby10@proton.me>
Depends: libc6, libgcc-s1, libxcb1, libxkbcommon0, libxkbcommon-x11-0
Recommends: mesa-vulkan-drivers
Section: net
Priority: optional
Description: VPN Client (GPUI)
 Connects to 3x-ui profiles over a system TUN device.
 Needs the privileged helper: sudo scripts/install-linux-helper.sh
EOF
DEB="$OUT/vpn-client_${VERSION}_amd64.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB" >/dev/null
echo "== $DEB"
sha256sum "$DEB"
