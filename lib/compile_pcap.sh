#!/bin/bash

set -e

LIBPCAP_SOURCE_DIR=./libpcap
LIBPCAP_INSTALL_DIR=$1/pcap
CONFIG_HOST=$3

echo "PCAP lib source dir: ${LIBPCAP_SOURCE_DIR}"
echo "PCAP lib install dir: ${LIBPCAP_INSTALL_DIR}"
echo "PCAP lib config host: ${CONFIG_HOST}"

rm -rf "${LIBPCAP_SOURCE_DIR}"
git clone --depth 1 --branch libpcap-1.10.1 https://github.com/the-tcpdump-group/libpcap

cd "${LIBPCAP_SOURCE_DIR}"
./configure --prefix=${LIBPCAP_INSTALL_DIR} --host=${CONFIG_HOST}
make
make install
make clean
cd ../
rm -rf "${LIBPCAP_SOURCE_DIR}"