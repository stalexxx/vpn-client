#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export TOOLCHAINS="${TOOLCHAINS:-com.apple.dt.toolchain.Metal.32023.922.4}"
export VPN_CLIENT_DEV_SOCKET="${VPN_CLIENT_DEV_SOCKET:-/private/tmp/vpn-gpui-live/control.sock}"
mkdir -p "$(dirname "$VPN_CLIENT_DEV_SOCKET")"
cd "$ROOT"
proc=""
stop() { if [ -n "$proc" ]; then kill "$proc" 2>/dev/null || true; wait "$proc" 2>/dev/null || true; fi; }
trap 'stop; exit 0' INT TERM EXIT
snapshot() { find gpui-client/src src ui -type f -exec stat -f '%m %N' {} \; 2>/dev/null; cat gpui-client/Cargo.toml; cat Cargo.toml; cat src-tauri/tauri.admin.conf.json; }
while true; do
  before="$(snapshot | shasum -a 256 | cut -d' ' -f1)"
  if ! cargo build --manifest-path gpui-client/Cargo.toml; then echo 'Build failed; waiting for another source change.'; fi
  proc=""
  if [ -x gpui-client/target/debug/vpn-gpui ]; then VPN_CLIENT_DEV_SOCKET="$VPN_CLIENT_DEV_SOCKET" gpui-client/target/debug/vpn-gpui & proc=$!; fi
  while true; do
    sleep 1
    after="$(snapshot | shasum -a 256 | cut -d' ' -f1)"
    if [ "$after" != "$before" ] || { [ -n "$proc" ] && ! kill -0 "$proc" 2>/dev/null; }; then stop; break; fi
  done
done
