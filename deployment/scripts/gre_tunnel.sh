#!/usr/bin/env bash
#ubuntu@host-2:~$ sudo ip tunnel add tun0 mode gre remote 10.131.73.9 local 10.131.73.16 dev eth0
#ubuntu@host-2:~$ sudo ip addr add 172.17.0.2/24 dev tun0
#ubuntu@host-2:~$ sudo ip link set tun0 up

TAP_IFACE=$1
TAP_IP=$2
LOCAL_IP=$3
REMOTE_IP=$4
INTERFACE=$5

if [ $# -lt 5 ]; then
    echo "Usage: ${0/*\//} <tap interface> <tap ip> <local ip> <remote ip> <interface>"
    exit 1
fi

echo
echo "Creating gre tunnel"

ip tunnel add ${TAP_IFACE} mode gretap remote ${REMOTE_IP} local ${LOCAL_IP} dev ${INTERFACE}
ip addr add ${TAP_IP} dev ${TAP_IFACE}
ip link set ${TAP_IFACE} up
