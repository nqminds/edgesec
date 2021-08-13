cmake_minimum_required(VERSION 3.0.0)
project(EDGESEC C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/lib")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/docs")

include(CTest)
include(FetchContent)
include(ExternalProject)
# include(CodeCoverage)
include(glibc)

option(USE_ARM_MUSL_LIBC "Use arm musl standard C library" OFF)
option(BUILD_ONLY_DOCS "Build only docs" OFF)
option(BUILD_CAPTURE_SERVICE "Build Capture server" ON)
option(BUILD_REST_SERVER "Build Rest server" ON)
option(BUILD_HOSTAPD "Build hostapd" OFF)
option(BUILD_SQLITE_LIB "Build sqlite3 library" ON)
option(BUILD_OPENSSL_LIB "Build OpenSSL" OFF)
option(BUILD_CMOCKA_LIB "Build cmocka library" ON)
option(BUILD_MNL_LIB "Build mnl library" ON)
option(BUILD_NETLINK_LIB "Build netlink library" ON)
option(BUILD_NL_LIB "Build nl library" OFF)
option(BUILD_MICROHTTPD_LIB "Build microhttpd library" OFF)
option(BUILD_UUID_LIB "Build uuid library" ON)
option(BUILD_PCAP_LIB "Build pcap library" OFF)
option(BUILD_NDPI_LIB "Build nDPI library" OFF)
option(BUILD_GRPC_LIB "Build gRPC library" OFF)
option(BUILD_SQLSYNC_SERVICE "Build sqlsync service" OFF)
option(BUILD_REVERSE_SERVICE "Build Reverse service" OFF)

option(USE_SQLITE3_LIB "Use sqlite3 library" ON)
option(USE_UUID_LIB "Use uuid library" ON)
option(USE_PTHREAD_LIB "Use pthread library" ON)
option(USE_M_LIB "Use m library" ON)
option(USE_OW_DNSMASQ "Use the OpenWrt dnsmasq service" OFF)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_SYSTEM_NAME Linux)
if (USE_ARM_MUSL_LIBC)
  set(CMAKE_SYSTEM_PROCESSOR arm)
  set(tools /usr/local/arm-linux-musleabihf)
  set(CMAKE_C_COMPILER /usr/local/bin/arm-linux-musleabihf-gcc)
  set(CMAKE_CXX_COMPILER /usr/local/bin/arm-linux-musleabihf-g++)
endif ()

# The edgesec version number.
set(EDGESEC_VERSION_MAJOR 0)
set(EDGESEC_VERSION_MINOR 3)
set(EDGESEC_VERSION_PATCH 0)

# The restsrv version number.
set(RESTSRV_VERSION_MAJOR 0)
set(RESTSRV_VERSION_MINOR 1)
set(RESTSRV_VERSION_PATCH 0)

# The capture version number.
set(CAPTURE_VERSION_MAJOR 0)
set(CAPTURE_VERSION_MINOR 1)
set(CAPTURE_VERSION_PATCH 0)

# The sqlite sync server version number.
set(SQLSYNCSRV_VERSION_MAJOR 0)
set(SQLSYNCSRV_VERSION_MINOR 1)
set(SQLSYNCSRV_VERSION_PATCH 0)

# The reverse client version number.
set(REVCLIENT_VERSION_MAJOR 0)
set(REVCLIENT_VERSION_MINOR 1)
set(REVCLIENT_VERSION_PATCH 0)

# The reverse server version number.
set(REVSRV_VERSION_MAJOR 0)
set(REVSRV_VERSION_MINOR 1)
set(REVSRV_VERSION_PATCH 0)

if (NOT USE_ARM_MUSL_LIBC)
  CHECK_GLIBC_VERSION()
endif ()

# Include the libraries
include(hostapd)
include(cmocka)
include(mnl)
include(netlink)
include(nl)
include(microhttpd)
include(uuid)
include(ndpi)
include(grpc)
include(openssl)
include(pcap)
include(sqlite)

if (USE_PTHREAD_LIB AND NOT (BUILD_ONLY_DOCS))
  find_library(LIBPTHREAD_LIB NAMES pthread libpthread)
  if (LIBPTHREAD_LIB)
    message("Found libpthread library: ${LIBPTHREAD_LIB}")
  ELSE ()
    message(FATAL_ERROR "Could not find libpthread library.")
  endif ()
endif ()

if (USE_M_LIB AND NOT (BUILD_ONLY_DOCS))
  find_library(LIBM_LIB NAMES m libm)
  if (LIBM_LIB)
    message("Found libm library: ${LIBM_LIB}")
  ELSE ()
    message(FATAL_ERROR "Could not find libm library.")
  endif ()
endif ()

if (BUILD_SQLSYNC_SERVICE AND NOT (BUILD_ONLY_DOCS))
  add_compile_definitions(WITH_SQLSYNC_SERVICE)

  # Generate grpc probuf sources
  get_filename_component(sqlite_proto "protos/sqlite_sync.proto" ABSOLUTE)
  get_filename_component(sqlite_proto_path "${sqlite_proto}" PATH)

  # Define protobuf generated sources paths
  set(sqlite_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/sqlite_sync.pb.cc")
  set(sqlite_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/sqlite_sync.pb.h")
  set(sqlite_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/sqlite_sync.grpc.pb.cc")
  set(sqlite_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/sqlite_sync.grpc.pb.h")

  add_custom_command(
    OUTPUT "${sqlite_proto_srcs}" "${sqlite_proto_hdrs}" "${sqlite_grpc_srcs}" "${sqlite_grpc_hdrs}"
    COMMAND ${_PROTOBUF_PROTOC}
    ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
      --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
      -I "${sqlite_proto_path}"
      --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
      "${sqlite_proto}"
    DEPENDS "${sqlite_proto}")

  add_library(sqlite_grpc_proto ${sqlite_grpc_srcs} ${sqlite_grpc_hdrs} ${sqlite_proto_srcs} ${sqlite_proto_hdrs})
  target_link_libraries(sqlite_grpc_proto ${_GRPC_GRPCPP})
endif ()

if (BUILD_REVERSE_SERVICE AND NOT (BUILD_ONLY_DOCS))
  get_filename_component(reverse_proto "protos/reverse_access.proto" ABSOLUTE)
  get_filename_component(reverse_proto_path "${reverse_proto}" PATH)

  set(reverse_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/reverse_access.pb.cc")
  set(reverse_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/reverse_access.pb.h")
  set(reverse_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/reverse_access.grpc.pb.cc")
  set(reverse_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/reverse_access.grpc.pb.h")

  add_custom_command(
    OUTPUT "${reverse_proto_srcs}" "${reverse_proto_hdrs}" "${reverse_grpc_srcs}" "${reverse_grpc_hdrs}"
    COMMAND ${_PROTOBUF_PROTOC}
    ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
      --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
      -I "${reverse_proto_path}"
      --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
      "${reverse_proto}"
    DEPENDS "${reverse_proto}")

  # Include generated *.pb.h files
  # include_directories("${CMAKE_CURRENT_BINARY_DIR}")

  # Compile grpc protobuf sources
  add_library(reverse_grpc_proto ${reverse_grpc_srcs} ${reverse_grpc_hdrs} ${reverse_proto_srcs} ${reverse_proto_hdrs})
  target_link_libraries(reverse_grpc_proto ${_GRPC_GRPCPP})
endif ()

if (USE_OW_DNSMASQ)
  add_compile_definitions(WITH_OW_DNSMASQ_SERVICE)
endif ()


# C compiler options
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-variable")

# Set the color for terminal logging
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLOG_USE_COLOR")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftest-coverage")

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG_LIBNL")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

# set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
set(CMAKE_INSTALL_RPATH "$ORIGIN" "$ORIGIN/lib")
set(CMAKE_INSTALL_PREFIX "${PROJECT_BINARY_DIR}/install" )

# configure a header file to pass some of the CMake settings
# to the source code
configure_file(
  "version.h.in"
  "${PROJECT_BINARY_DIR}/version.h"
)

# Copy the default configuration file to the build folder
configure_file(
  "config.ini.in"
  "${PROJECT_BINARY_DIR}/config.ini"
)

include(doxygen)

if (NOT BUILD_ONLY_DOCS)
  add_subdirectory(src)
  add_subdirectory(tests)
endif ()

install(
  TARGETS edgesec capsrv
  RUNTIME DESTINATION "bin"
)

if (BUILD_REST_SERVER AND LIBMICROHTTPD_LIB)
  install(
    TARGETS restsrv
    RUNTIME DESTINATION "bin"
  )
endif ()

if (BUILD_SQLSYNC_SERVICE AND LIBSQLITE_LIB)
  install(
    TARGETS sqlsyncsrv
    RUNTIME DESTINATION "bin"
  )
endif ()

if (BUILD_REVERSE_SERVICE)
  install(
    TARGETS revclient revsrv
    RUNTIME DESTINATION "bin"
  )
endif ()

install(FILES "${PROJECT_BINARY_DIR}/config.ini" DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")

if (BUILD_UUID_LIB AND LIBUUID_LIB)
  install(DIRECTORY ${LIBUUID_LIB_DIR} DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif ()

if (BUILD_SQLITE_LIB AND LIBSQLITE_LIB)
  install(DIRECTORY ${LIBSQLITE_LIB_DIR} DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif ()

if(BUILD_PCAP_LIB AND LIBPCAP_LIB)
  install(DIRECTORY ${LIBPCAP_LIB_DIR} DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif ()

if(BUILD_OPENSSL_LIB AND LIBCRYPTO_LIB)
  install(DIRECTORY ${LIBOPENSSL_LIB_PATH} DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif ()

if (BUILD_NETLINK_LIB AND LIBNETLINK_LIB)
  install(DIRECTORY ${LIBNETLINK_LIB_PATH} DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif ()

if (BUILD_NDPI_LIB AND LIBNDPI_LIB)
  install(DIRECTORY ${LIBNDPI_LIB_DIR} DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif ()

if (BUILD_MNL_LIB AND LIBMNL_LIB)
  install(DIRECTORY ${LIBMNL_LIB_DIR} DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif ()

if (BUILD_MICROHTTPD_LIB AND LIBMICROHTTPD_LIB)
  install(DIRECTORY ${LIBMICROHTTPD_LIB_DIR} DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif ()

if (BUILD_HOSTAPD AND HOSTAPD)
  install(FILES ${HOSTAPD} DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif ()
# setup_target_for_coverage_lcov(
#   NAME coverage
#   EXECUTABLE /home/alexandru/Projects/EDGESec/build/src/edgesec -c /home/alexandru/Projects/EDGESec/build/config.ini -dddddddd -s 12345
#   BASE_DIRECTORY "${PROJECT_BINARY_DIR}"
# )

#
# add_subdirectory("${GRPC_SOURCE_DIR}/third_party/re2" EXCLUDE_FROM_ALL)
