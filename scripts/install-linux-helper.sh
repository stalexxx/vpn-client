#!/bin/bash
# Installs vpn-tun-helper as a root systemd service on Linux.
# Build first: cargo build --release --bin vpn-tun-helper
#   GOOS_LIST=linux GOARCH_LIST=amd64 tools/awgsocks/build.sh <amneziawg-go checkout>
# usage: sudo scripts/install-linux-helper.sh
# Env: SRC_DIR (default: <repo>/target/release), AWG_BIN, XRAY_BIN (default: download
#   the official Xray-linux-64 release), GEO_DIR (dir with geoip.dat/geosite.dat).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }
USER="${SUDO_USER:-root}"
[ "$USER" != root ] || { echo "run with sudo from the user account that will use the VPN (SUDO_USER is empty)" >&2; exit 1; }
HELPER_UID="$(id -u "$USER")"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
[ -n "$VERSION" ] || { echo "cannot read version from Cargo.toml" >&2; exit 1; }

SRC="${SRC_DIR:-$ROOT/target/release}"
HELPER="$SRC/vpn-tun-helper"
AWG="${AWG_BIN:-$ROOT/assets/awgsocks-linux-amd64}"
[ -x "$HELPER" ] || { echo "build first: cargo build --release --bin vpn-tun-helper" >&2; exit 1; }
[ -x "$AWG" ] || { echo "awgsocks missing: $AWG (GOOS_LIST=linux GOARCH_LIST=amd64 tools/awgsocks/build.sh <checkout>)" >&2; exit 1; }

DEST=/usr/local/lib/vpnclient
ASSETS=/var/lib/vpnclient-assets

status() { # $1 = field; prints it when the helper answers
  python3 -c '
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5)
try: s.connect("/var/run/vpnclient-tun.sock")
except OSError: sys.exit(1)
s.sendall(b"{\"action\":\"status\"}\n")
print(json.loads(s.recv(65536).decode()).get(sys.argv[1], ""))
' "$1" 2>/dev/null
}
if [ "$(status connected)" = True ]; then
  echo "Отключите VPN перед обновлением системного компонента, затем повторите." >&2; exit 1
fi
if systemctl is-active --quiet vpnclient-helper 2>/dev/null; then
  systemctl stop vpnclient-helper
fi

XRAY_OUT="$(mktemp -d)"; trap 'rm -rf "$XRAY_OUT"' EXIT
if [ -n "${XRAY_BIN:-}" ]; then
  [ -x "$XRAY_BIN" ] || { echo "xray not found: $XRAY_BIN (set XRAY_BIN)" >&2; exit 1; }
  cp "$XRAY_BIN" "$XRAY_OUT/xray"
else
  command -v unzip >/dev/null || { echo "need unzip or XRAY_BIN" >&2; exit 1; }
  curl -fsSL -o "$XRAY_OUT/xray.zip" https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
  unzip -q -o "$XRAY_OUT/xray.zip" xray geoip.dat geosite.dat -d "$XRAY_OUT"
fi
chmod 755 "$XRAY_OUT/xray"

install -d -o root -g root -m 755 "$DEST" "$ASSETS"
install -o root -g root -m 755 "$HELPER" "$DEST/vpn-tun-helper"
install -o root -g root -m 755 "$AWG" "$DEST/awgsocks"
install -o root -g root -m 755 "$XRAY_OUT/xray" "$DEST/xray"
for f in geoip.dat geosite.dat; do
  if [ -n "${GEO_DIR:-}" ] && [ -f "$GEO_DIR/$f" ]; then install -o root -g root -m 644 "$GEO_DIR/$f" "$ASSETS/$f"
  elif [ -f "$XRAY_OUT/$f" ]; then install -o root -g root -m 644 "$XRAY_OUT/$f" "$ASSETS/$f"; fi
done

cat > /etc/systemd/system/vpnclient-helper.service <<EOF
[Unit]
Description=VPN Client TUN helper ($VERSION)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$DEST/vpn-tun-helper serve $HELPER_UID $DEST/xray --system
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now vpnclient-helper

for _ in $(seq 1 80); do
  [ "$(status version)" = "$VERSION" ] && { echo "helper $VERSION active for $USER (uid $HELPER_UID)"; exit 0; }
  sleep 0.1
done
echo "service installed but not answering with $VERSION; see journalctl -u vpnclient-helper" >&2; exit 1
