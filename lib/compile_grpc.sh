#!/bin/bash

set -e

set -e

LIBGRPC_SOURCE_DIR=./grpc
LIBGRPC_INSTALL_DIR=$1/grpc
CONFIG_HOST=$2

echo "GRPC lib source dir: ${LIBGRPC_SOURCE_DIR}"
echo "GRPC lib install dir: ${LIBGRPC_INSTALL_DIR}"
echo "GRPC lib config host: ${CONFIG_HOST}"

rm -rf "${LIBGRPC_SOURCE_DIR}"
git clone --depth 1 --branch v1.36.4 https://github.com/grpc/grpc

cd ${LIBGRPC_SOURCE_DIR}

# Just before installing gRPC, wipe out contents of all the submodules to simulate
# a standalone build from an archive
# shellcheck disable=SC2016
git submodule foreach 'cd $toplevel; rm -rf $name'

# Install gRPC
mkdir -p "cmake/build"
pushd "cmake/build"
cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DgRPC_INSTALL=ON \
  -DgRPC_BUILD_TESTS=OFF \
  -DgRPC_CARES_PROVIDER=package \
  -DgRPC_ABSL_PROVIDER=package \
  -DgRPC_PROTOBUF_PROVIDER=package \
  -DgRPC_RE2_PROVIDER=package \
  -DgRPC_SSL_PROVIDER=package \
  -DgRPC_ZLIB_PROVIDER=package \
  -DCMAKE_INSTALL_PREFIX=$LIBGRPC_INSTALL_DIR \
  ../..
make -j4 install
popd