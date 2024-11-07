#!/bin/bash

### Copy from Cursor
### BEGIN INIT INFO
# Provides:          iptables-config
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Apply iptables rules
### END INIT INFO

# Instructions:
#
# sudo chmod +x /etc/init.d/iptables-config
#
# sudo chkconfig --add iptables-config
#
# sudo chkconfig iptables-config on
#
# sudo service iptables-config start
#
# sudo iptables -t nat -L -n -v --line-number
#
# sudo iptables -L -n -v
# delete a rule by line number 7
# sudo iptables -t nat -D PREROUTING 7
#
# sysctl.conf
# echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
# echo "net.ipv4.conf.all.route_localnet=1" | sudo tee -a /etc/sysctl.conf
# echo "net.ipv4.conf.default.route_localnet=1" | sudo tee -a /etc/sysctl.conf
# reload sysctl config
# sudo sysctl -p

# clear all rules
iptables -F
iptables -t nat -F

# add default policy
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# add DNAT rule for port 443
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:1200
iptables -t nat -A POSTROUTING -o lo -j MASQUERADE

# add filter rules
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 1200 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -p tcp --sport 443 -j ACCEPT

exit 0