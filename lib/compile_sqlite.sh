#!/bin/bash

set -e

LIBSQLITE_SOURCE_DIR=$1
LIBSQLITE_INSTALL_DIR=$2/sqlite
CONFIG_HOST=$3

echo "SQLITE lib source dir: ${LIBSQLITE_SOURCE_DIR}"
echo "SQLITE lib install dir: ${LIBSQLITE_INSTALL_DIR}"
echo "SQLITE lib config host: ${CONFIG_HOST}"

cd "${LIBSQLITE_SOURCE_DIR}"
autoreconf -f -i
./configure --prefix=${LIBSQLITE_INSTALL_DIR} --host=${CONFIG_HOST}
make
make install
make clean
