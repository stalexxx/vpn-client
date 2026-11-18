#!/bin/bash
# Runs the GPUI client on a headless Linux box (dummy Xorg + software Vulkan).
# usage: ./scripts/run-gpui-linux.sh
# Needs (once): cargo build --release --manifest-path gpui-client/Cargo.toml
#   and: apt install xserver-xorg-video-dummy mesa-vulkan-drivers libxkbcommon-x11-0 x11-apps
# View: DISPLAY=:98 scrot shot.png | Click: x11vnc -display :98 -localhost, then VNC to this host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${VPN_GPUI_BIN:-$ROOT/gpui-client/target/release/vpn-gpui}"
[ -x "$APP" ] || { echo "build first: cargo build --release --manifest-path gpui-client/Cargo.toml" >&2; exit 1; }
if ! DISPLAY=:98 xdpyinfo >/dev/null 2>&1; then
  echo "starting dummy Xorg :98"
  nohup /usr/lib/xorg/Xorg :98 -noreset -config "$ROOT/scripts/xorg-dummy.conf" -logfile /tmp/xorg.log >/dev/null 2>&1 &
  for _ in $(seq 1 50); do DISPLAY=:98 xdpyinfo >/dev/null 2>&1 && break; sleep 0.2; done
  DISPLAY=:98 xdpyinfo >/dev/null 2>&1 || { echo "Xorg :98 failed; see /tmp/xorg.log" >&2; exit 1; }
fi
# GPUI presents a frame only on Expose; a bare Xorg sends none after mapping,
# so poke it periodically (also keeps pings/traffic repainting for VNC viewers).
(while true; do DISPLAY=:98 xrefresh >/dev/null 2>&1; sleep 2; done &)
export DISPLAY=:98 VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json
exec "$APP"
