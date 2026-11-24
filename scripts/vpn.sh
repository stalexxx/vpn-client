#!/bin/bash
# Talks to vpn-tun-helper over its Unix socket (works on macOS and Linux).
# usage: scripts/vpn.sh status | start <link> [relay-link] | stop | stats | log [lines] [filter] | log-level [info|warning] | autoconnect [on|off]
set -euo pipefail
action="${1:-status}"
python3 - "$action" "$@" <<'EOF'
import json, socket, sys
action, args = sys.argv[1], sys.argv[2:]
req = {"action": action}
if action == "start":
    if len(args) < 2: sys.exit("usage: vpn.sh start <link> [relay-link]")
    req["link"] = args[1]
    if len(args) > 2: req["relay_link"] = args[2]
elif action == "log":
    if len(args) > 1: req["lines"] = int(args[1])
    if len(args) > 2: req["filter"] = args[2]
elif action == "log-level":
    if len(args) > 1: req = {"action": "set_log_level", "level": args[1]}
    else: req = {"action": "get_log_level"}
elif action == "autoconnect":
    if len(args) > 1:
        val = args[1].lower()
        if val in ("on", "1", "enable", "enabled"): req = {"action": "set_autoconnect", "enabled": True}
        elif val in ("off", "0", "disable", "disabled"): req = {"action": "set_autoconnect", "enabled": False}
        else: sys.exit("usage: vpn.sh autoconnect [on|off]")
    else: req = {"action": "get_autoconnect"}
elif action not in ("status", "stop", "stats"):
    sys.exit("usage: vpn.sh status | start <link> [relay-link] | stop | stats | log [lines] [filter] | log-level [info|warning] | autoconnect [on|off]")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(70 if action == "start" else 20)
try: s.connect("/var/run/vpnclient-tun.sock")
except OSError as e: sys.exit(f"helper недоступен: {e}")
s.sendall((json.dumps(req) + "\n").encode())
data = b""
while not data.endswith(b"\n"): data += s.recv(65536)
r = json.loads(data.decode())
print(("OK " if r.get("ok") else "FAIL ") + r.get("message", ""))
if action == "status": print("connected:", r.get("connected"), "| version:", r.get("version"))
sys.exit(0 if r.get("ok") else 1)
EOF
