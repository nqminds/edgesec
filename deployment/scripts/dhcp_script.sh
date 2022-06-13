#!/bin/sh
str="SET_IP $1 $2 $3"
echo "Sending $str ..."
echo $str | nc -uU /tmp/edgesec-control-server -w2 -W1
