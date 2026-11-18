#!/bin/sh
# Builds the embedded AmneziaWG client into assets/ (default: macOS arm64 + x86_64).
# usage: tools/awgsocks/build.sh /path/to/amneziawg-go   (checkout of github.com/amnezia-vpn/amneziawg-go, commit b5928ef)
# Env: GOOS_LIST (default "darwin"), GOARCH_LIST (default "arm64 amd64").
# Example: GOOS_LIST=linux GOARCH_LIST=amd64 tools/awgsocks/build.sh ~/src/amneziawg-go
set -eu
SRC="${1:?path to amneziawg-go checkout}"
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="$HERE/../../assets"
mkdir -p "$SRC/cmd/awgsocks"
cp "$HERE/main.go" "$SRC/cmd/awgsocks/main.go"
for os in ${GOOS_LIST:-darwin}; do
  cp "$HERE/bindiface_${os}.go" "$SRC/conn/bindiface_${os}.go"
  for arch in ${GOARCH_LIST:-"arm64 amd64"}; do
    (cd "$SRC" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$OUT/awgsocks-$os-$arch" ./cmd/awgsocks)
  done
  ls -la "$OUT"/awgsocks-$os-*
done
