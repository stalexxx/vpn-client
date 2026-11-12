#!/bin/bash
# Installs AmneziaWG (userspace amneziawg-go) with Cloudflare WARP as the exit. Env: AWG_PORT, AWG_SHA256. Binary expected at /root/amneziawg-go.upload.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
# Errors go to stderr too: the app shows the last stderr line as the reason for a failed install.
fail(){ echo "ERROR $*" >&2; exit 4; }
echo "$AWG_SHA256  /root/amneziawg-go.upload" | sha256sum -c - >/dev/null || { echo "ERROR checksum" >&2; exit 3; }
install -m755 /root/amneziawg-go.upload /usr/local/bin/amneziawg-go && rm -f /root/amneziawg-go.upload
# amneziawg-tools (awg, awg-quick) come from one of two sources, chosen in the app:
#   github (default): a pinned GitHub tag built here; works wherever GitHub and the Ubuntu archive are reachable.
#   ppa: Amnezia's Launchpad PPA (prebuilt packages); needs launchpad.net and keyserver.ubuntu.com.
AWG_TOOLS=${AWG_TOOLS:-github}
AWG_TOOLS_REF=v3.1.20260812
AWG_TOOLS_COMMIT=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
if ! command -v awg >/dev/null || ! command -v awg-quick >/dev/null; then
  case "$AWG_TOOLS" in
    github)
      echo "== apt: инструменты сборки"
      timeout 300 apt-get update || fail "apt-get update не завершился (таймаут 5 мин или нет доступа к репозиториям Ubuntu)"
      timeout 900 apt-get install -y make gcc libc6-dev git curl iptables || fail "не удалось установить make, gcc, libc6-dev, git, curl, iptables"
      echo "== amneziawg-tools $AWG_TOOLS_REF с GitHub"
      rm -rf /root/amneziawg-tools
      timeout 300 git clone --depth 1 --branch "$AWG_TOOLS_REF" https://github.com/amnezia-vpn/amneziawg-tools.git /root/amneziawg-tools || fail "не удалось скачать amneziawg-tools с GitHub"
      [ "$(git -C /root/amneziawg-tools rev-parse HEAD)" = "$AWG_TOOLS_COMMIT" ] || fail "commit amneziawg-tools не совпадает с закреплённым ($AWG_TOOLS_COMMIT)"
      make -C /root/amneziawg-tools/src -j"$(nproc)" || fail "сборка amneziawg-tools не удалась"
      make -C /root/amneziawg-tools/src install WITH_WGQUICK=yes WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no || fail "установка amneziawg-tools не удалась"
      rm -rf /root/amneziawg-tools
      ;;
    ppa)
      echo "== apt: пакеты для PPA"
      timeout 300 apt-get update || fail "apt-get update не завершился (таймаут 5 мин или нет доступа к репозиториям Ubuntu)"
      timeout 600 apt-get install -y software-properties-common gnupg2 curl iptables || fail "не удалось установить software-properties-common, gnupg2, curl, iptables"
      echo "== PPA ppa:amnezia/ppa (launchpad.net и keyserver.ubuntu.com)"
      timeout 120 add-apt-repository -y ppa:amnezia/ppa || fail "PPA ppa:amnezia/ppa недоступен с сервера: нет доступа к launchpad.net или keyserver.ubuntu.com. Выберите сборку с GitHub"
      timeout 300 apt-get update || fail "apt-get update после подключения PPA не завершился"
      echo "== amneziawg-tools из PPA"
      timeout 600 apt-get install -y amneziawg-tools || fail "не удалось установить amneziawg-tools из PPA"
      ;;
    *) fail "неизвестный источник amneziawg-tools: $AWG_TOOLS" ;;
  esac
  command -v awg-quick >/dev/null && command -v awg >/dev/null || fail "awg/awg-quick не появились после установки"
fi
PORT=${AWG_PORT:-47821}; SUBNET=10.8.1; DIR=/etc/amnezia/amneziawg
export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
mkdir -p $DIR; umask 077
sysctl -w net.ipv4.ip_forward=1 >/dev/null; echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-awg.conf
# server keys
[ -f $DIR/server.key ] || awg genkey > $DIR/server.key
awg pubkey < $DIR/server.key > $DIR/server.pub
# WARP registration
if [ ! -f $DIR/warp.json ]; then
  awg genkey > $DIR/warp.key; awg pubkey < $DIR/warp.key > $DIR/warp.pub
  curl -fsS -m20 -X POST https://api.cloudflareclient.com/v0a2158/reg -H 'Content-Type: application/json' -H 'CF-Client-Version: a-6.3-1922' -H 'User-Agent: okhttp/3.12.1' \
    -d "{\"key\":\"$(cat $DIR/warp.pub)\",\"install_id\":\"\",\"fcm_token\":\"\",\"tos\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\",\"type\":\"Android\",\"model\":\"PC\",\"locale\":\"en_US\"}" > $DIR/warp.json
fi
read WPUB WV4 < <(python3 -c "import json;c=json.load(open('$DIR/warp.json'))['config'];print(c['peers'][0]['public_key'],c['interface']['addresses']['v4'])")
cat > $DIR/warp0.conf <<C
[Interface]
PrivateKey = $(cat $DIR/warp.key)
Address = $WV4/32
MTU = 1280
Table = off
[Peer]
PublicKey = $WPUB
AllowedIPs = 0.0.0.0/0
Endpoint = 162.159.192.1:2408
PersistentKeepalive = 25
C
# obfuscation parameters (fixed after first generation)
if [ ! -f $DIR/obf.env ]; then
  r(){ shuf -i "$1" -n1; }
  S1=$(r 15-150); S2=$(r 15-150); while [ $((S1+56)) -eq $S2 ]; do S2=$(r 15-150); done
  { echo "Jc=$(r 4-12)"; echo "Jmin=50"; echo "Jmax=1000"; echo "S1=$S1"; echo "S2=$S2"
    for i in 1 2 3 4; do echo "H$i=$(r 5-2000000000)"; done; } > $DIR/obf.env
fi
. $DIR/obf.env
EXT=$(ip route show default | awk '{print $5; exit}')
# A re-run must keep existing clients: their "# client <name>" blocks are carried over from the old awg0.conf.
CLIENTS=""; [ -f $DIR/awg0.conf ] && CLIENTS=$(sed -n '/^# client /,$p' $DIR/awg0.conf || true)
cat > $DIR/awg0.conf <<C
[Interface]
PrivateKey = $(cat $DIR/server.key)
Address = $SUBNET.1/24
MTU = 1280
ListenPort = $PORT
Jc = $Jc
Jmin = $Jmin
Jmax = $Jmax
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
PostUp = ip rule add from $SUBNET.0/24 lookup 100 priority 100; ip route replace blackhole default metric 2000 table 100; ip route replace default dev warp0 table 100; iptables -I FORWARD -i awg0 -j ACCEPT; iptables -I FORWARD -o awg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -I POSTROUTING -s $SUBNET.0/24 -o warp0 -j MASQUERADE
PostDown = ip rule del from $SUBNET.0/24 lookup 100 priority 100 || true; ip route flush table 100 || true; iptables -D FORWARD -i awg0 -j ACCEPT || true; iptables -D FORWARD -o awg0 -m state --state RELATED,ESTABLISHED -j ACCEPT || true; iptables -t nat -D POSTROUTING -s $SUBNET.0/24 -o warp0 -j MASQUERADE || true
C
[ -n "$CLIENTS" ] && printf '\n%s\n' "$CLIENTS" >> $DIR/awg0.conf
# systemd units
for n in warp0 awg0; do
cat > /etc/systemd/system/awg-quick@$n.service <<U
[Unit]
Description=AmneziaWG $n
After=network-online.target
$( [ $n = awg0 ] && echo "After=awg-quick@warp0.service
Requires=awg-quick@warp0.service" )
[Service]
Type=oneshot
RemainAfterExit=yes
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
ExecStart=/usr/bin/awg-quick up $DIR/$n.conf
ExecStop=/usr/bin/awg-quick down $DIR/$n.conf
[Install]
WantedBy=multi-user.target
U
done
# Ubuntu images often run ufw with "deny incoming": without a rule the AmneziaWG UDP port drops every client packet.
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then ufw allow "$PORT"/udp comment 'AmneziaWG' >/dev/null; fi
# Some hosts keep an nftables input allowlist (table inet audit_filter, default drop): ufw alone does not open the port there.
if nft list table inet audit_filter >/dev/null 2>&1; then
  nft list chain inet audit_filter input | grep -q "udp dport $PORT accept" || nft add rule inet audit_filter input udp dport "$PORT" accept
  if [ -f /etc/nftables.conf ] && ! sed -n '/^table inet audit_filter/,/^}/p' /etc/nftables.conf | grep -qE "udp dport .*\b$PORT\b"; then
    cp -p /etc/nftables.conf /etc/nftables.conf.bak-awg
    sed -i -E "/^table inet audit_filter/,/^}/ s/^([[:space:]]*)udp dport \{(.*)\} accept(.*)$/\1udp dport {\2, $PORT} accept   # AmneziaWG\3/" /etc/nftables.conf
  fi
fi
systemctl daemon-reload
systemctl enable --now awg-quick@warp0 awg-quick@awg0
echo "PORT=$PORT SERVER_PUB=$(cat $DIR/server.pub)"
