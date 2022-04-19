#!/bin/sh
bindname="/tmp/socat-edgesec.sock"
rm -f $bindname
echo -n $1 | socat unix-client:/tmp/edgesec-domain-server,type=2,bind=$bindname -
