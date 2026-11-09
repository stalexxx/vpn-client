#!/bin/bash
# usage: viewclient.sh <name>: prints the saved client config
f=/etc/amnezia/amneziawg/clients/${1:?name}.conf
[ -f "$f" ] || { echo "NOCONF" >&2; exit 5; }
cat "$f"
