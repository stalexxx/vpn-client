#!/bin/bash
# usage: delclient.sh <name>: removes the peer block "# client <name>" from awg0.conf and from the live interface
set -euo pipefail
D=/etc/amnezia/amneziawg; N=${1:?name}; export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
PUB=$(python3 - "$D/awg0.conf" "$N" <<'PY'
import sys,re
path,name=sys.argv[1:]
text=open(path).read()
parts=re.split(r'(?m)^(?=# client )',text)
keep=[];pub=None
for p in parts:
    if p.startswith(f'# client {name}\n'):
        m=re.search(r'PublicKey = (\S+)',p); pub=m.group(1) if m else None
    else: keep.append(p)
if pub is None: sys.exit(4)
open(path,'w').write(''.join(keep).rstrip('\n')+'\n')
print(pub)
PY
)
awg set awg0 peer "$PUB" remove
rm -f "$D/clients/$N.conf"
echo removed
