#!/bin/bash

set -e

util_linux_SOURCE_DIR=$1
LIBUUID_INSTALL_DIR=$2/uuid
CONFIG_HOST=$3

echo "util-linux source dir: ${util_linux_SOURCE_DIR}"
echo "UUID lib install dir: ${LIBUUID_INSTALL_DIR}"
echo "UUID lib config host: ${CONFIG_HOST}"

cd "${util_linux_SOURCE_DIR}"
# for some reason, on Elementary OS 5, we need to manually set AL_OPTS
AL_OPTS="-I/usr/share/aclocal" ./autogen.sh
./configure \
    --prefix=${LIBUUID_INSTALL_DIR} --host=${CONFIG_HOST} \
    --disable-all-programs --enable-libuuid

# Load LIB_MAKEFLAGS from CMake if set
export MAKEFLAGS="${MAKEFLAGS-""} ${LIB_MAKEFLAGS-""}"

make
make install-strip # make install, except with symbols removed
make distclean
