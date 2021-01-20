#!/bin/sh

set -e

linkfile="/etc/systemd/network/10-persistent-net.link"

[ -z "$1" ] && echo "No WiFi input interface specified" && exit 1
[ -z "$2" ] && echo "No WiFi output interface specified" && exit 1

ifname=`ip --json a show $1 | jq -r '.'[0].ifname`
address=`ip --json a show $1 | jq -r '.'[0].address`

[ -z "$ifname" ] && exit 1
[ -z "$address" ] && exit 1

echo "Setting the predictable interface from $1 to $2 with MAC=$address"

> $linkfile

echo "[Match]" >> $linkfile
echo "MACAddress=$address" >> $linkfile
echo "" >> $linkfile
echo "[Link]" >> $linkfile
echo "Name=$2" >> $linkfile

echo "You can restart the machine"