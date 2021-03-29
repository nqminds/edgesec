#!/bin/bash

set -e

MY_PATH="`dirname \"$0\"`"              # relative
MY_PATH="`( cd \"$MY_PATH\" && pwd )`"  # absolutized and normalized
if [ -z "$MY_PATH" ] ; then
  # error; for some reason, the path is not accessible
  # to the script (e.g. permissions re-evaled after suid)
  exit 1  # fail
fi

GRPC_BUILD_PATH=${MY_PATH}/grpc/cmake/build
echo "Building $MY_PATH"

cd ${MY_PATH}/grpc

# Install absl
# mkdir -p "third_party/abseil-cpp/cmake/build"
# pushd "third_party/abseil-cpp/cmake/build"
# cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE ../..
# make -j4 install
# popd

# Install c-ares
# If the distribution provides a new-enough version of c-ares,
# this section can be replaced with:
# apt-get install -y libc-ares-dev
# mkdir -p "third_party/cares/cares/cmake/build"
# pushd "third_party/cares/cares/cmake/build"
# cmake -DCMAKE_BUILD_TYPE=Release ../..
# make -j4 install
# popd

# Install protobuf
mkdir -p "third_party/protobuf/cmake/build"
pushd "third_party/protobuf/cmake/build"
cmake -Dprotobuf_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release ..
make -j4 install
popd

# Install re2
# mkdir -p "third_party/re2/cmake/build"
# pushd "third_party/re2/cmake/build"
# cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE ../..
# make -j4 install
# popd

# Install zlib
# mkdir -p "third_party/zlib/cmake/build"
# pushd "third_party/zlib/cmake/build"
# cmake -DCMAKE_BUILD_TYPE=Release ../..
# make -j4 install
# popd
