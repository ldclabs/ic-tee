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
# 设置脚本权限
# sudo chmod +x /etc/init.d/iptables-config
# 将脚本添加到系统服务
# sudo chkconfig --add iptables-config
# 设置开机自启
# sudo chkconfig iptables-config on
# 如果想立即运行脚本测试
# sudo service iptables-config start
# 查看所有 NAT 规则
# sudo iptables -t nat -L -n -v  --line-number
# 查看所有 filter 规则
# sudo iptables -L -n -v
# delete a rule by line number 7
# sudo iptables -t nat -D PREROUTING 7
#
# sysctl.conf
# echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
# echo "net.ipv4.conf.all.route_localnet=1" | sudo tee -a /etc/sysctl.conf
# echo "net.ipv4.conf.default.route_localnet=1" | sudo tee -a /etc/sysctl.conf
# 重新加载配置
# sudo sysctl -p

# 清除现有规则
iptables -F
iptables -t nat -F

# 设置默认策略
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# NAT 规则
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:1200
iptables -t nat -A POSTROUTING -o lo -j MASQUERADE

# filter 规则
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 1200 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -p tcp --sport 443 -j ACCEPT

exit 0