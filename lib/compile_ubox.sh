#!/bin/bash

set -e

LIBUBOX_SOURCE_DIR=$1
LIBUBOX_INSTALL_DIR=$2
CMAKE_SYSTEM_NAME=$3
CMAKE_SYSTEM_PROCESSOR=$4
CMAKE_C_COMPILER=$5

echo "UBOX lib source dir: ${LIBUBOX_SOURCE_DIR}"
echo "UBOX lib install dir: ${LIBUBOX_INSTALL_DIR}"
echo "UBOX lib system name: ${CMAKE_SYSTEM_NAME}"
echo "UBOX lib system processor: ${CMAKE_SYSTEM_PROCESSOR}"
echo "UBOX lib C compiler: ${CMAKE_C_COMPILER}"

cd "${LIBUBOX_SOURCE_DIR}"

rm -rf build/
mkdir build/
cd build/

cmake ../ -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF \
    -DCMAKE_INSTALL_PREFIX=${LIBUBOX_INSTALL_DIR} \
    -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME} \
    -DCMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR} \
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}

make
make install
