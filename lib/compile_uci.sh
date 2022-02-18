#!/bin/bash

set -e

LIBUCI_SOURCE_DIR=$1
LIBUCI_INSTALL_DIR=$2
LIBUBOX_INCLUDE_PATH=$3
LIBUBOX_LIB=$4
LIBUBOX_STATIC_LIB=$5
CMAKE_SYSTEM_NAME=$6
CMAKE_SYSTEM_PROCESSOR=$7
CMAKE_C_COMPILER=$8

echo "UCI lib source dir: ${LIBUCI_SOURCE_DIR}"
echo "UCI lib install dir: ${LIBUCI_INSTALL_DIR}"
echo "UCI lib ubox library include path: ${LIBUBOX_INCLUDE_PATH}"
echo "UCI lib ubox shared library path: ${LIBUBOX_LIB}"
echo "UCI lib ubox static library path: ${LIBUBOX_STATIC_LIB}"
echo "UCI lib system name: ${CMAKE_SYSTEM_NAME}"
echo "UCI lib system processor: ${CMAKE_SYSTEM_PROCESSOR}"
echo "UCI lib C compiler: ${CMAKE_C_COMPILER}"

cd "${LIBUCI_SOURCE_DIR}"

rm -rf build/
mkdir build/
cd build/

cmake ../ -DBUILD_LUA=OFF -DBUILD_STATIC=ON \
    -DCMAKE_INSTALL_PREFIX=${LIBUCI_INSTALL_DIR} \
    -Dubox_include_dir=${LIBUBOX_INCLUDE_PATH} \
    -Dubox=${LIBUBOX_LIB} \
    -Dubox-static=${LIBUBOX_STATIC_LIB} \
    -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME} \
    -DCMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR} \
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}

make
make install


# The install target "uci-static" does not exist in the CMakeLists.txt
# so we copy to the lib install folder
cp ${LIBUCI_SOURCE_DIR}/build/libuci.a ${LIBUCI_INSTALL_DIR}/lib