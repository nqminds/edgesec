#!/bin/bash

set -e

MY_PATH="`dirname \"$0\"`"              # relative
MY_PATH="`( cd \"$MY_PATH\" && pwd )`"  # absolutized and normalized
if [ -z "$MY_PATH" ] ; then
  # error; for some reason, the path is not accessible
  # to the script (e.g. permissions re-evaled after suid)
  exit 1  # fail
fi
echo "Building $MY_PATH on $1"

INSTALL_PATH="$1/netlink"

cd ${MY_PATH}/libnetlink

rm -rf build/

mkdir build
mkdir "${INSTALL_PATH}"

cd build/

cmake -DLIB_PATH:STRING=$1 -DC_COMPILER:STRING=$2 -DCXX_COMPILER:STRING=$3 ../

make


cmake --install . --prefix "${INSTALL_PATH}"

cd ../

cp -a include/ "${INSTALL_PATH}"

rm -rf build/
