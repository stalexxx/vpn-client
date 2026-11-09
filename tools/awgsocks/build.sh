#!/bin/sh
# Builds the embedded AmneziaWG client for macOS (arm64 + x86_64) into assets/.
# usage: tools/awgsocks/build.sh /path/to/amneziawg-go   (checkout of github.com/amnezia-vpn/amneziawg-go, commit b5928ef)
set -eu
SRC="${1:?path to amneziawg-go checkout}"
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="$HERE/../../assets"
mkdir -p "$SRC/cmd/awgsocks"
cp "$HERE/main.go" "$SRC/cmd/awgsocks/main.go"
cp "$HERE/bindiface_darwin.go" "$SRC/conn/bindiface_darwin.go"
for arch in arm64 amd64; do
  (cd "$SRC" && CGO_ENABLED=0 GOOS=darwin GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$OUT/awgsocks-darwin-$arch" ./cmd/awgsocks)
done
ls -la "$OUT"/awgsocks-darwin-*
