#!/bin/bash
set -uo pipefail
systemctl disable --now awg-quick@awg0 awg-quick@warp0 2>/dev/null
rm -f /etc/systemd/system/awg-quick@awg0.service /etc/systemd/system/awg-quick@warp0.service /etc/sysctl.d/99-awg.conf /usr/local/bin/amneziawg-go
rm -rf /etc/amnezia/amneziawg
systemctl daemon-reload
echo removed
