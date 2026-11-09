#!/bin/bash
# Installs AmneziaWG (userspace amneziawg-go) with Cloudflare WARP as the exit. Env: AWG_PORT, AWG_SHA256. Binary expected at /root/amneziawg-go.upload.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo "$AWG_SHA256  /root/amneziawg-go.upload" | sha256sum -c - >/dev/null || { echo "ERROR checksum"; exit 3; }
install -m755 /root/amneziawg-go.upload /usr/local/bin/amneziawg-go && rm -f /root/amneziawg-go.upload
if ! command -v awg-quick >/dev/null; then
  apt-get update -qq; apt-get install -y -qq software-properties-common gnupg2 curl iptables >/dev/null
  add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1; apt-get update -qq
  apt-get install -y -qq amneziawg-tools >/dev/null
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
systemctl daemon-reload
systemctl enable --now awg-quick@warp0 awg-quick@awg0
echo "PORT=$PORT SERVER_PUB=$(cat $DIR/server.pub)"
