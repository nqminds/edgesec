#!/bin/bash

set -e

LIBGRPC_SOURCE_DIR="$1"
LIBGRPC_BUILD_DIR="$2"
LIBGRPC_INSTALL_DIR="$3/grpc"
CONFIG_HOST="$4"

echo "GRPC lib source dir: ${LIBGRPC_SOURCE_DIR}"
echo "GRPC lib build dir: ${LIBGRPC_BUILD_DIR}"
echo "GRPC lib install dir: ${LIBGRPC_INSTALL_DIR}"
echo "GRPC lib config host: ${CONFIG_HOST}"

# Install gRPC
mkdir -p "${LIBGRPC_BUILD_DIR}"
pushd "${LIBGRPC_BUILD_DIR}"
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
  "${LIBGRPC_SOURCE_DIR}"
make -j9 install
popd
