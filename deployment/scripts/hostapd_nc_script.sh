#!/bin/sh

# Use Ctr-D to send the command when in nc intercative mode
echo -n $1 | sudo nc -uU /var/run/hostapd/wifiap0 -w2 -W1
