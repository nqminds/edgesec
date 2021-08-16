#!/bin/bash

set -e

LIBOPENSSL_SOURCE_DIR=./openssl
LIBOPENSSL_INSTALL_DIR=$1/openssl
CONFIG_HOST=$3

echo "OPENSSL lib source dir: ${LIBOPENSSL_SOURCE_DIR}"
echo "OPENSSL lib install dir: ${LIBOPENSSL_INSTALL_DIR}"
echo "OPENSSL lib config host: ${CONFIG_HOST}"

rm -rf "${LIBOPENSSL_SOURCE_DIR}"

git clone --depth 1 --branch openssl-3.0.0-beta1 https://github.com/openssl/openssl

cd "${LIBOPENSSL_SOURCE_DIR}"

./Configure --prefix=${LIBOPENSSL_INSTALL_DIR} --openssldir=${LIBOPENSSL_INSTALL_DIR} no-dtls no-dtls1 no-psk no-srp no-ec2m no-weak-ssl-ciphers
make
make install
make clean

cd ../
rm -rf "${LIBOPENSSL_SOURCE_DIR}"
