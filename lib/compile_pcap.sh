#!/bin/bash

set -e

LIBPCAP_SOURCE_DIR="$1"
LIBPCAP_BUILD_DIR="$2"
LIBPCAP_INSTALL_DIR="$3/pcap"
CONFIG_HOST="$4"

echo "PCAP lib source dir: ${LIBPCAP_SOURCE_DIR}"
echo "PCAP lib build dir: ${LIBPCAP_BUILD_DIR}"
echo "PCAP lib install dir: ${LIBPCAP_INSTALL_DIR}"
echo "PCAP lib config host: ${CONFIG_HOST}"

cd "${LIBPCAP_BUILD_DIR}"
"${LIBPCAP_SOURCE_DIR}"/configure --prefix="${LIBPCAP_INSTALL_DIR}" --host="${CONFIG_HOST}"

# Load LIB_MAKEFLAGS from CMake if set
export MAKEFLAGS="${MAKEFLAGS-""} ${LIB_MAKEFLAGS-""}"

make
make install
