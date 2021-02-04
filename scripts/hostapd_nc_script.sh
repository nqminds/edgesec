#!/bin/sh

echo -n $1 | sudo nc -uU /var/run/hostapd/wifiap0 -w2 -W1