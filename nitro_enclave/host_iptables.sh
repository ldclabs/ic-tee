# route local incoming packets on port 8080 to the transparent proxy
iptables -t nat -A OUTPUT -p tcp --dport 8080 -o lo -j REDIRECT --to-port 1200
iptables -t nat -A OUTPUT -p tcp --dport 8080 -d 127.0.0.1 -j REDIRECT --to-port 1200

# route incoming packets on port 443 to the transparent proxy
iptables -A PREROUTING -t nat -p tcp --dport 443 -i ens5 -j REDIRECT --to-port 1200
# route incoming packets on port 1025:65535 to the transparent proxy
# iptables -A PREROUTING -t nat -p tcp --dport 1025:65535 -i ens5 -j REDIRECT --to-port 1200

iptables -L -t nat -v -n --line-number
# delete a rule by line number 7
# sudo iptables -t nat -D PREROUTING 7