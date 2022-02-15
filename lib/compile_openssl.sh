#!/bin/bash

set -e

LIBOPENSSL_SOURCE_DIR="$1"
LIBOPENSSL_INSTALL_DIR="$2"
CONFIG_HOST="$3"
CONFIG_PREFIX="$4"

echo "OPENSSL lib source dir: ${LIBOPENSSL_SOURCE_DIR}"
echo "OPENSSL lib install dir: ${LIBOPENSSL_INSTALL_DIR}"
echo "OPENSSL lib cross-compile config host: ${CONFIG_HOST}"
echo "OPENSSL lib cross-compile config prefix: ${CONFIG_PREFIX}"

cd "${LIBOPENSSL_SOURCE_DIR}"

# CONFIG_HOST is UNQUOTED, so that OpenSSL picks default if it's not set
# Set --libdir=lib, since otherwise sometimes OpenSSL installs in /lib64
# ./Configure ${CONFIG_HOST} --cross-compile-prefix=${CONFIG_PREFIX} --prefix=${LIBOPENSSL_INSTALL_DIR} --libdir=lib --openssldir=${LIBOPENSSL_INSTALL_DIR} -lpthread no-dtls no-dtls1 no-psk no-srp no-ec2m no-weak-ssl-ciphers no-dso no-engine no-threads no-unit-test
./Configure ${CONFIG_HOST} --prefix=${LIBOPENSSL_INSTALL_DIR} --libdir=lib --openssldir=${LIBOPENSSL_INSTALL_DIR} -lpthread no-dtls no-dtls1 no-psk no-srp no-ec2m no-weak-ssl-ciphers no-dso no-engine no-threads no-unit-test

# Load LIB_MAKEFLAGS from CMake if set
export MAKEFLAGS="${MAKEFLAGS-""} ${LIB_MAKEFLAGS-""}"
echo "Compiling OpenSSL with MAKEFLAGS=$MAKEFLAGS"
make
# only install software, don't install or build docs
make install_sw
