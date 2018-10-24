############<-- IPv4 -->###############
#!/bin/bash
 
# Delete all existing rules and classes
iptables -F && iptables -X
iptables -P INPUT DROP && iptables -P FORWARD DROP && iptables -P OUTPUT ACCEPT

#Accept loopback input aka allow localhost
iptables -A INPUT -i lo -p all -j ACCEPT

# Drop all input let only conform packets trough
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

### DROPspoofing packets
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 192.168.0.0/24 -j DROP

iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

#for SMURF attack protection
#iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
#iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
#iptables -A INPUT -p icmp -m icmp -m limit --limit 1/second -j ACCEPT

#Block invalid packets
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

# flooding of RST packets, smurf attack Rejection
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Block [NULL] Packets
iptables -A INPUT  -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT  -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix 'NULL Packets'

iptables -A INPUT  -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT  -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Block [XMAS] Packets
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix 'XMAS Packets'
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# Block [FIN] Packets Scan
iptables -A INPUT  -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix 'FIN Packets Scan'
iptables -A INPUT  -p tcp --tcp-flags FIN,ACK FIN -j DROP

# Block other common pits
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Protecting portscans
# Attacking IP will be locked for 24 hours (3600 x 24 = 86400 Seconds)
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Remove attacking IP after 24 hours
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# These rules add scanners to the portscan list, and log the attempt.
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

#NO PING SCAN BRAH
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j DROP

# Enable logging for all IPv4 traffic
iptables -A INPUT -j LOG && iptables -A FORWARD -j LOG && iptables -A OUTPUT -j LOG

# Lastly reject All INPUT traffic
iptables -A INPUT -j REJECT

################# Below are for OUTPUT iptables rules #############################################

## Allow loopback OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow the following ports through from outside
# SMTP = 25
# DNS =53
# HTTP = 80
# HTTPS = 443
# SSH = 22
### You can also add or remove port no. as per your requirement

#iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT
#iptables -A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT

# Allow pings
iptables -A OUTPUT -p icmp -m icmp --icmp-type 8 -j DROP

# Lastly Reject all Output traffic
#iptables -A OUTPUT -j REJECT

## Reject Forwarding  traffic
iptables -A FORWARD -j REJECT