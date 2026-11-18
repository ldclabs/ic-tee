#!/bin/sh
set -e

# setting an address for loopback
ifconfig lo 127.0.0.1
ifconfig

# Debian: failed to initialize nft: Protocol not supported
update-alternatives --set iptables /usr/sbin/iptables-legacy

# adding a default route
ip route add default via 127.0.0.1 dev lo
route -n

# iptables rules to route traffic to transparent proxy
iptables -A OUTPUT -t nat -p tcp --dport 1:65535 ! -d 127.0.0.1  -j DNAT --to-destination 127.0.0.1:448
# redirect all traffic to port 9999 to the transparent proxy, for logtail server
iptables -A OUTPUT -t nat -p tcp --dport 9999 -j DNAT --to-destination 127.0.0.1:448
# replace the source address with 127.0.0.1 for outgoing packets with a source of 0.0.0.0
# ensures returning packets have 127.0.0.1 as the destination and not 0.0.0.0
iptables -A POSTROUTING -t nat -o lo -s 0.0.0.0 -j SNAT --to-source 127.0.0.1
iptables -L -t nat -v -n

# your custom setup goes here

exec /app/supervisord
