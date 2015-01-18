#!/bin/sh

## This script tests the firewall from all devices
## You should copy it to all devices and run from each.

PUBIP=192.168.1.1

if [ `hostname` = "6262-rtr" ]; then

#Testing HTTP from Router  to PUB (REJECTED)
wget http://192.168.1.1

#Testing SMTP from Router to PUB (REJECTED)
nc -vz 192.168.1.1 25

#Testing SSH from Router to PUB (REJECTED)
nc -vz 192.168.1.1 22

#Testing HTTP from Router to Internet (REJECTED)
wget http://10.0.0.16

#Testing SMTP from Router to Internet (REJECTED)
nc -vz 10.0.2.16 25

fi
	
if [ `hostname` = "6262-wkstn" ]; then
	#run commands from workstation

#Testing HTTP from Workstations to PUB (ACCEPTED)
wget http://192.168.1.1

#Testing SMTP from Workstations to PUB (ACCEPTED)
nc -vz 192.168.1.1 25

#Testing SSH from Workstations to PUB (ACCEPTED)
nc -vz 192.168.1.1 22

#Testing SSH from Workstation to Router (ACCEPTED)
nc -vz 10.0.2.15 22

#Testing HTTP From Workstations to Internet (ACCEPTED)
wget http://10.0.2.16

#Testing SMTP From Workstations to Internet (REJECTED)
nc -vz 10.0.2.16 25

#Testing DNS From Workstations to PUB (ACCEPTED)
nc -vu 192.168.1.1 53

#Testing DNS from Workstation to Internet (REJECTED)
nc -vu 10.0.2.16 53
fi

if [ `hostname` = "6262-pub" ]; then
	#run commands from public server

#Testing SSH from PUB to Router (REJECTED)
nc -vz 10.0.2.15 22

#Testing HTTP from PUB to Internet (REJECTED)
wget http://10.0.2.16

#Testing SMTP from PUB to Internet (ACCEPTED)
nc -vz 10.0.2.16 25

#Testing DNS from PUB to Internet (ACCEPTED)
nc -vu 10.0.2.16 53

fi

if [ `hostname` = "6262-inet" ]; then
	#run commands from the "internet"

#Testing HTTP from Internet to PUB (ACCEPTED)
wget http://192.168.1.1

#Testing SMTP from Internet to PUB (ACCEPTED)
nc -vz 192.168.1.1 25
 
#Testing SSH from Internet to PUB (REJECTED)
nc -vz 192.168.1.1 22

#Testing SSH from Internet to Router (REJECTED)
nc -vz 10.0.2.15 22

#Testing DNS from Internet to PUB (ACCEPTED)
nc -vu 192.168.1.1 53

fi

if [ `hostname` = "6262-intserv" ]; then
	#run commands from the "internal server"

#Testing HTTP from INT SERVER  to PUB (REJECTED)
wget http://192.168.1.1

#Testing SMTP from INT SERVER to PUB (REJECTED)
nc -vz 192.168.1.1 25

#Testing SSH from INT SERVER to PUB (REJECTED)
nc -vz 192.168.1.1 22

#Testing SSH from INT SERVER to ROUTER (REJECTED)
nc -vz 10.0.2.15 22

#Testing HTTP from INT SERVER to Internet (REJECTED)
wget http://10.0.0.16

#Testing SMTP from INT SERVER to Internet (REJECTED)
nc -vz 10.0.2.16 25

#Testing DNS from INT SERVER to PUB (REJECTED)
nc -vu 192.168.1.1 53

#Testing DNS from INT SERVER to Internet (REJECTED)
nc -vu 10.0.2.16 53

fi
