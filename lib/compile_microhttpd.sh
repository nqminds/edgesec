#!/bin/bash

set -e

LIBMICROHTTPD_SOURCE_DIR=$1
LIBMICROHTTPD_INSTALL_DIR=$2/libmicrohttpd
CONFIG_HOST=$3

echo "MICROHTTPD lib source dir: ${LIBMICROHTTPD_SOURCE_DIR}"
echo "MICROHTTPD lib install dir: ${LIBMICROHTTPD_INSTALL_DIR}"
echo "MICROHTTPD lib config host: ${CONFIG_HOST}"

cd "${LIBMICROHTTPD_SOURCE_DIR}"
# autoreconf -f -i
./configure --prefix=${LIBMICROHTTPD_INSTALL_DIR} --host=${CONFIG_HOST}
make
make install
make distclean

