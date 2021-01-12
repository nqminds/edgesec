#!/bin/bash

set -e

MY_PATH="`dirname \"$0\"`"              # relative
MY_PATH="`( cd \"$MY_PATH\" && pwd )`"  # absolutized and normalized
if [ -z "$MY_PATH" ] ; then
  # error; for some reason, the path is not accessible
  # to the script (e.g. permissions re-evaled after suid)
  exit 1  # fail
fi
echo "Building $MY_PATH"

cd ${MY_PATH}/libnetlink

rm -rf build/

mkdir build

cd build/

cmake -DLIBMNL_PATH:STRING=${MY_PATH}/libmnl-1.0.4 ../

make

