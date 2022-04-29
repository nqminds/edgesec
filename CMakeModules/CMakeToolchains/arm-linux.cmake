cmake_minimum_required(VERSION 3.9.0)

# relies on toolchain being installed in /usr/local

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CROSS_COMPILE_PREFIX /usr/local/bin/arm-linux-musleabihf-)
set(CMAKE_LIBRARY_ARCHITECTURE arm-linux-musleabihf)

#  set(CROSS_COMPILE_PREFIX /usr/local/bin/aarch64-linux-musl-)
set(CMAKE_C_COMPILER "${CROSS_COMPILE_PREFIX}gcc")
set(CMAKE_CXX_COMPILER "${CROSS_COMPILE_PREFIX}g++")
set(CMAKE_STRIP "${CROSS_COMPILE_PREFIX}strip")
