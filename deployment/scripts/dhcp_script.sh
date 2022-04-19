#!/bin/sh
str="SET_IP $1 $2 $3"
echo "Sending $str ..."
echo $str | nc -uU /tmp/edgesec-domain-server -w2 -W1
