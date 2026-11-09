#!/bin/bash
# usage: awg-addclient.sh <name>  -> prints client .conf (AmneziaWG), registers the peer live and in awg0.conf
set -euo pipefail
D=/etc/amnezia/amneziawg; N=${1:?name}; export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
. $D/obf.env; umask 077
KEY=$(awg genkey); PUB=$(echo "$KEY" | awg pubkey); PSK=$(awg genpsk)
USED=$(grep -o 'AllowedIPs = 10\.8\.1\.[0-9]*' $D/awg0.conf | grep -o '[0-9]*$' | sort -n | tail -1 || true)
IP=10.8.1.$(( ${USED:-1} + 1 ))
PORT=$(grep ListenPort $D/awg0.conf | awk '{print $3}'); HOST=$(curl -fsS -m5 https://api.ipify.org --interface "$(ip route show default | awk '{print $5; exit}')")
printf '\n# client %s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n' "$N" "$PUB" "$PSK" "$IP" >> $D/awg0.conf
echo "$PSK" > /run/awg-psk.$$; awg set awg0 peer "$PUB" preshared-key /run/awg-psk.$$ allowed-ips "$IP/32"; rm -f /run/awg-psk.$$
mkdir -p $D/clients
cat > $D/clients/$N.conf <<C
[Interface]
PrivateKey = $KEY
Address = $IP/32
DNS = 1.1.1.1
Jc = $Jc
Jmin = $Jmin
Jmax = $Jmax
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4

[Peer]
PublicKey = $(cat $D/server.pub)
PresharedKey = $PSK
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $HOST:$PORT
PersistentKeepalive = 25
C
cat $D/clients/$N.conf
