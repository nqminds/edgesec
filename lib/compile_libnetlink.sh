#!/bin/bash

set -e


LIBNETLINK_SOURCE_DIR=$1
LIBNETLINK_INSTALL_ROOT=$2
LIBNETLINK_INSTALL_DIR=${LIBNETLINK_INSTALL_ROOT}/netlink
LIBMNL_INSTALL_DIR=${LIBNETLINK_INSTALL_ROOT}/mnl
C_COMPILER=$3
CXX_COMPILER=$4

echo "NETLINK lib source dir: ${LIBNETLINK_SOURCE_DIR}"
echo "NETLINK lib install dir: ${LIBNETLINK_INSTALL_DIR}"
echo "NETLINK lib config C compiler: ${C_COMPILER}"
echo "NETLINK lib config CXX compiler: ${CXX_COMPILER}"

cd "${LIBNETLINK_SOURCE_DIR}"

rm -rf build/

mkdir build
mkdir "${LIBNETLINK_INSTALL_DIR}"

cd build/

cmake -DLIB_PATH:STRING=${LIBMNL_INSTALL_DIR} -DC_COMPILER:STRING=${C_COMPILER} -DCXX_COMPILER:STRING=${CXX_COMPILER} ../

make


cmake --install . --prefix "${LIBNETLINK_INSTALL_DIR}"

cd ../

cp -a include/ "${LIBNETLINK_INSTALL_DIR}"

rm -rf build/
