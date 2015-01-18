#!/bin/sh


## This script specifies the firewall rules for assignment 4
## Run as root

##NAMES: #TODO 

## =========== IP Tables Policies ============
iptables -F
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A FORWARD -i eth0 -o eth1 -m state --state NEW,ESTABLISHED -p tcp -d 192.168.1.1/24 -m multiport --dports 80,25 -j ACCEPT 
iptables -A FORWARD -i eth1 -o eth0 -m state --state ESTABLISHED -p tcp -s 192.168.1.1/24 -m multiport --sports 80,25 -j ACCEPT

iptables -A FORWARD ! -i eth1 -p udp ! -s 172.16.1.1 -d 192.168.1.1/24 --dport 53 -j ACCEPT
iptables -A FORWARD ! -o eth1 -p udp -s 192.168.1.1/24 ! -d 172.16.1.1 --sport 53 -j ACCEPT

#iptables -A FORWARD -i eth0 -p udp -d 192.168.1.1/24 --dport 53 -j ACCEPT
#iptables -A FORWARD -o eth0 -p udp -s 192.168.1.1/25 --sport 53 -j ACCEPT

#iptables -A FORWARD -i eth2 -p udp ! -s 172.16.1.1 -d 192.168.1.1/24 --dport 53 -j ACCEPT
#iptables -A FORWARD -o eth2 -p udp -s 192.168.1.1/24 ! -d 172.16.1.1 --sport 53 -j ACCEPT

iptables -A FORWARD -o eth0 -p udp -s 192.168.1.1/24 --dport 53 -j ACCEPT
iptables -A FORWARD -i eth0 -p udp -d 192.168.1.1/24 --sport 53 -j ACCEPT

iptables -A FORWARD -i eth1 -o eth0 -m state --state NEW,ESTABLISHED -p tcp -s 192.168.1.1/24 --dport 25 -j ACCEPT 
iptables -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED -p tcp -d 192.168.1.1/24 --sport 25 -j ACCEPT

iptables -A FORWARD -i eth2 -o eth0 -m state --state NEW,ESTABLISHED -p tcp ! -s 172.16.1.1 --dport 80 -j ACCEPT
iptables -A FORWARD -i eth0 -o eth2 -m state --state ESTABLISHED -p tcp ! -d 172.16.1.1 --sport 80 -j ACCEPT

iptables -A FORWARD -i eth2 -m state --state NEW,ESTABLISHED -p tcp ! -s 172.16.1.1 -d 192.168.1.1/24 -m multiport --dports 80,22,25 -j ACCEPT
iptables -A FORWARD -o eth2 -m state --state ESTABLISHED -p tcp ! -d 172.16.1.1 -s 192.168.1.1/24 -m multiport --sports 80,22,25 -j ACCEPT

iptables -A INPUT -p tcp -s 172.16.1.2 -m state --state NEW,ESTABLISHED -d 10.0.2.15 --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp -s 10.0.2.15 -m state --state ESTABLISHED -d 172.16.1.2 --sport 22 -j ACCEPT

#======== HELPFUL HINTS:
# eth0 : 10.0.2.15 : Internet interface
# eth1 : 192.168.1.100 : External network interface
# eth2 : 172.16.1.100 : Internal network interface
# List iptables rules: # iptables -L -n -v --line-numbers

