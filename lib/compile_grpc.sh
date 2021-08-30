#!/bin/bash

set -e

LIBGRPC_SOURCE_DIR=./grpc
LIBGRPC_INSTALL_DIR=$1/grpc
CONFIG_HOST=$2

echo "GRPC lib source dir: ${LIBGRPC_SOURCE_DIR}"
echo "GRPC lib install dir: ${LIBGRPC_INSTALL_DIR}"
echo "GRPC lib config host: ${CONFIG_HOST}"

rm -rf "${LIBGRPC_SOURCE_DIR}"
git clone -b v1.36.4 https://github.com/grpc/grpc

cd ${LIBGRPC_SOURCE_DIR}
git submodule update --init

# Install gRPC
mkdir -p "cmake/build"
pushd "cmake/build"
cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DgRPC_INSTALL=ON \
  -DgRPC_BUILD_TESTS=OFF \
  -DCMAKE_CXX_FLAGS=-latomic \
  -DgRPC_CARES_PROVIDER=module \
  -DgRPC_ABSL_PROVIDER=module \
  -DgRPC_PROTOBUF_PROVIDER=module \
  -DgRPC_RE2_PROVIDER=module \
  -DgRPC_SSL_PROVIDER=module \
  -DgRPC_ZLIB_PROVIDER=module \
  -DCMAKE_INSTALL_RPATH=\$ORIGIN \
  -DCMAKE_INSTALL_PREFIX=$LIBGRPC_INSTALL_DIR \
  ../..
make -j4 install
popd

rm -rf "${LIBGRPC_SOURCE_DIR}"