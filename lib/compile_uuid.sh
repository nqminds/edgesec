#!/bin/bash

set -e

LIBUUID_SOURCE_DIR=$1
LIBUUID_INSTALL_DIR=$2/uuid
CONFIG_HOST=$3

echo "UUID lib source dir: ${LIBUUID_SOURCE_DIR}"
echo "UUID lib install dir: ${LIBUUID_INSTALL_DIR}"
echo "UUID lib config host: ${CONFIG_HOST}"

cd "${LIBUUID_SOURCE_DIR}"
autoreconf -f -i
./configure --prefix=${LIBUUID_INSTALL_DIR} --host=${CONFIG_HOST}
make
make install
make distclean
