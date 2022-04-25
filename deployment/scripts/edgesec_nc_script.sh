#!/bin/sh

echo -n $1 | sudo nc -uU /tmp/edgesec-domain-server -w2 -W1
