#!/bin/sh

echo -n $1 | sudo nc -uU /tmp/edgesec-control-server -w2 -W1
