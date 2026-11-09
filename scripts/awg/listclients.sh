#!/bin/bash
# prints "name ip" per client
awk '/^# client /{n=$3} /^AllowedIPs = 10\.8\.1\./{print n, $3}' /etc/amnezia/amneziawg/awg0.conf
