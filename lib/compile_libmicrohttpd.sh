#!/bin/bash

set -e

MY_PATH="`dirname \"$0\"`"              # relative
MY_PATH="`( cd \"$MY_PATH\" && pwd )`"  # absolutized and normalized
if [ -z "$MY_PATH" ] ; then
  # error; for some reason, the path is not accessible
  # to the script (e.g. permissions re-evaled after suid)
  exit 1  # fail
fi
LIBMNL_PATH=${MY_PATH}/libmicrohttpd-0.9.72
BUILD_PATH=${LIBMNL_PATH}/build
echo "Building in ${LIBMNL_PATH}"

cd ${LIBMNL_PATH}
rm -rf build/
mkdir build

./configure --prefix=${BUILD_PATH}
make
make install
make clean
