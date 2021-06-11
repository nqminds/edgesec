cmake_minimum_required(VERSION 3.0.0)
project(EDGESEC C CXX)

include(CTest)
include(FetchContent)
include(ExternalProject)

option(BUILD_ONLY_DOCS "Build only docs" OFF)
option(BUILD_CAPTURE_SERVICE "Build Capture server" ON)
option(BUILD_REST_SERVER "Build Rest server" ON)
option(BUILD_HOSTAPD "Build hostapd" ON)
option(BUILD_CMOCKA_LIB "Build cmocka library" ON)
option(BUILD_MNL_LIB "Build mnl library" ON)
option(BUILD_NETLINK_LIB "Build netlin library" ON)
option(BUILD_MICROHTTPD_LIB "Build microhttpd library" ON)
option(USE_PCAP_LIB "Use pcap library" ON)
option(USE_SQLITE3_LIB "Use sqlite3 library" ON)
option(USE_UUID_LIB "Use uuid library" ON)
option(USE_PTHREAD_LIB "Use pthread library" ON)
option(USE_M_LIB "Use m library" ON)
option(BUILD_NDPI_LIB "Build nDPI library" ON)
option(BUILD_GRPC_LIB "Build gRPC library" OFF)
option(BUILD_SQLSYNC_SERVICE "Build sqlsync service" OFF)
option(BUILD_REVERSE_SERVICE "Build Reverse service" OFF)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_SYSTEM_NAME Linux)
# set(CMAKE_SYSTEM_PROCESSOR arm)
# set(tools /usr/local/arm-linux-musleabihf)
# set(CMAKE_C_COMPILER /usr/local/bin/arm-linux-musleabihf-gcc)
# set(CMAKE_CXX_COMPILER /usr/local/bin/arm-linux-musleabihf-g++)

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

# Find the hostapd program
if (BUILD_HOSTAPD AND NOT (BUILD_ONLY_DOCS))
  find_program(HOSTAPD NAMES hostapd PATHS "${CMAKE_SOURCE_DIR}/build")
  if (HOSTAPD)
    message("Found hostapd program: ${HOSTAPD}")
  ELSE ()
    execute_process(COMMAND bash "${CMAKE_SOURCE_DIR}/lib/compile_hostap.sh")
  endif ()
endif ()

# Compile the cmocka library
if (BUILD_CMOCKA_LIB AND NOT (BUILD_ONLY_DOCS))
  set(CMOCKA_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/cmocka-1.1.5/include")
  find_library(CMOCKA_LIB NAMES cmocka PATHS "${CMAKE_SOURCE_DIR}/lib/cmocka-1.1.5/build/src")
  if (CMOCKA_LIB)
    message("Found cmocka library: ${CMOCKA_LIB}")
  ELSE ()
    execute_process(COMMAND bash "${CMAKE_SOURCE_DIR}/lib/compile_cmocka.sh")
    find_library(CMOCKA_LIB NAMES cmocka PATHS "${CMAKE_SOURCE_DIR}/lib/cmocka-1.1.5/build/src")
  endif ()
endif ()

# Compile libmnl library used for libnetlink
if (BUILD_MNL_LIB AND NOT (BUILD_ONLY_DOCS))
  find_library(LIBMNL_LIB NAMES mnl PATHS "${CMAKE_SOURCE_DIR}/lib/libmnl-1.0.4/build/lib")
  if (LIBMNL_LIB)
    message("Found libmnl library: ${LIBMNL_LIB}")
  ELSE ()
    execute_process(COMMAND bash "${CMAKE_SOURCE_DIR}/lib/compile_libmnl.sh")
  endif ()
endif ()

# Compile library libnetlink
if (BUILD_NETLINK_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBNETLINK_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/libnetlink/include")
  set(LIBNETLINK_UAPI_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/libnetlink/include/uapi")
  find_library(LIBNETLINK_LIB NAMES libnetlink PATHS "${CMAKE_SOURCE_DIR}/lib/libnetlink/build/lib")
  if (LIBNETLINK_LIB)
    message("Found libnetlink library: ${LIBNETLINK_LIB}")
  ELSE ()
    execute_process(COMMAND bash "${CMAKE_SOURCE_DIR}/lib/compile_libnetlink.sh")
    find_library(LIBNETLINK_LIB NAMES libnetlink PATHS "${CMAKE_SOURCE_DIR}/lib/libnetlink/build/lib")
  endif ()
  find_library(LL_MAP_LIB NAMES ll_map PATHS "${CMAKE_SOURCE_DIR}/lib/libnetlink/build/lib")
  message("Found ll_map library: ${LL_MAP_LIB}")
  find_library(UTILS_LIB NAMES utils PATHS "${CMAKE_SOURCE_DIR}/lib/libnetlink/build/lib")
  message("Found utils library: ${UTILS_LIB}")
  find_library(RT_NAMES_LIB NAMES rt_names PATHS "${CMAKE_SOURCE_DIR}/lib/libnetlink/build/lib")
  message("Found rt_names library: ${RT_NAMES_LIB}")
  find_library(LL_TYPES_LIB NAMES ll_types PATHS "${CMAKE_SOURCE_DIR}/lib/libnetlink/build/lib")
  message("Found ll_types library: ${LL_TYPES_LIB}")
  find_library(LL_PROTO_LIB NAMES ll_proto PATHS "${CMAKE_SOURCE_DIR}/lib/libnetlink/build/lib")
  message("Found ll_types library: ${LL_PROTO_LIB}")

  find_path(LibNL_INCLUDE_DIR netlink/netlink.h
  	/usr/include
  	/usr/include/libnl3
  	/usr/local/include
  	/usr/local/include/libnl3
  )

  find_library(LibNL_LIBRARY NAMES nl nl-3)
  # find_library(LibNL_ROUTE_LIBRARY NAMES nl-route nl-route-3)
  # find_library(LibNL_NETFILTER_LIBRARY NAMES nl-nf nl-nf-3)
  find_library(LibNL_GENL_LIBRARY NAMES nl-genl nl-genl-3)

  if (LibNL_INCLUDE_DIR AND LibNL_LIBRARY)
  	set(LibNL_FOUND TRUE)
  endif ()

  if (LibNL_FOUND)
  	if (NOT LibNL_FIND_QUIETLY)
      message("Found netlink library: ${LibNL_LIBRARY}")
      # message("Found netlink route library: ${LibNL_ROUTE_LIBRARY}")
      # message("Found netlink netfilter library: ${LibNL_NETFILTER_LIBRARY}")
      message("Found netlink genl library: ${LibNL_GENL_LIBRARY}")
      message("Found netlink includes: ${LibNL_INCLUDE_DIR}")
  	endif ()
  ELSE ()
  	if (LibNL_FIND_REQUIRED)
  		message("Netlink version 3 development packages cannot be found.")
  		message("In Debian/Ubuntu, they may be called:")
  		message("libnl-3-dev libnl-genl-3dev libnl-nf-3-dev libnl-route-3-dev")
  		message(FATAL_ERROR "Could not find netlink library.")
  	endif ()
  endif ()
endif ()

# Compile libmicrohttpd-0.9.72
if (BUILD_MICROHTTPD_LIB AND NOT (BUILD_ONLY_DOCS))
  find_library(LIBMICROHTTPD_LIB NAMES microhttpd PATHS "${CMAKE_SOURCE_DIR}/lib/libmicrohttpd-0.9.72/build/lib")
  set(LIBMICROHTTPD_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/libmicrohttpd-0.9.72/build/include")
  if (LIBMICROHTTPD_LIB)
    message("Found libmicrohttpd library: ${LIBMICROHTTPD_LIB}")
  ELSE ()
    execute_process(COMMAND bash "${CMAKE_SOURCE_DIR}/lib/compile_libmicrohttpd.sh")
    find_library(LIBMICROHTTPD_LIB NAMES microhttpd PATHS "${CMAKE_SOURCE_DIR}/lib/libmicrohttpd-0.9.72/build/lib")
  endif ()
endif ()

if (USE_PCAP_LIB AND NOT (BUILD_ONLY_DOCS))
  find_library(LIBPCAP_LIB NAMES pcap)
  if (LIBPCAP_LIB)
    message("Found libpcap library: ${LIBPCAP_LIB}")
  ELSE ()
    message(FATAL_ERROR "Could not find pcap library.")
  endif ()
endif ()

if (USE_SQLITE3_LIB AND NOT (BUILD_ONLY_DOCS))
  find_library(LIBSQLITE3_LIB NAMES sqlite3)
  if (LIBSQLITE3_LIB)
    message("Found libsqlite3 library: ${LIBSQLITE3_LIB}")
  ELSE ()
    message(FATAL_ERROR "Could not find libsqlite3 library.")
  endif ()
endif ()

if (USE_UUID_LIB AND NOT (BUILD_ONLY_DOCS))
  find_library(LIBUUID_LIB NAMES uuid libuuid)
  if (LIBUUID_LIB)
    message("Found libuuid library: ${LIBUUID_LIB}")
  ELSE ()
    message(FATAL_ERROR "Could not find libuuid library.")
  endif ()
endif ()

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

if (BUILD_NDPI_LIB AND NOT (BUILD_ONLY_DOCS))
  add_compile_definitions(WITH_NDPI_SERVICE)
  set(LIBNDPI_PATH ${CMAKE_CURRENT_BINARY_DIR}/lib/ndpi)
  set(LIBNDPI_INCLUDE_PATH ${LIBNDPI_PATH}/include/ndpi)
  find_library(LIBNDPI_LIB_PATH NAMES ndpi libndpi PATHS "${LIBNDPI_PATH}/lib")
  if (LIBNDPI_LIB_PATH)
    message("Found libndpi library: ${LIBNDPI_LIB_PATH}")
  ELSE ()
    ExternalProject_Add(ndpi
      GIT_REPOSITORY  https://github.com/ntop/nDPI
      GIT_TAG         64929a75e0a7a60d864bd25a9fd97fdf9ac892a2
      GIT_PROGRESS    true
      CONFIGURE_COMMAND ./autogen.sh
      COMMAND           ./configure --prefix=${LIBNDPI_PATH}
      BUILD_IN_SOURCE     1
      BUILD_COMMAND       make  
    )
  endif ()
endif ()

# Fetch and Compile libgrpc
if (BUILD_GRPC_LIB AND NOT (BUILD_ONLY_DOCS))
  set(RE2_BUILD_TESTING OFF)
  FetchContent_Declare(
    gRPC
    GIT_REPOSITORY https://github.com/grpc/grpc
    GIT_TAG        v1.36.4
  )
  set(FETCHCONTENT_QUIET OFF)
  FetchContent_MakeAvailable(gRPC)
  FetchContent_GetProperties(gRPC SOURCE_DIR GRPC_SOURCE_DIR)
  message("${GRPC_SOURCE_DIR}/third_party/re2")
  set(_PROTOBUF_LIBPROTOBUF libprotobuf)
  set(_REFLECTION grpc++_reflection)
  set(_PROTOBUF_PROTOC $<TARGET_FILE:protoc>)
  set(_GRPC_GRPCPP grpc++)
  set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)  
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

# C compiler options
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-variable")

# Set the color for terminal logging
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLOG_USE_COLOR")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG_LIBNL")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

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

# check if Doxygen is installed
find_package(Doxygen)

if (DOXYGEN_FOUND)
    # set input and output files
    set(DOXYGEN_IN Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    # Doxygen.in file parameters
    set(DOXYGEN_INPUT "src docs")
    set(DOXYGEN_IMAGE_PATH docs)
    set(DOXYGEN_DOTFILE_DIRS docs)
    set(DOXYGEN_OUTPUT_DIRECTORY docs)
    # request to configure the file
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    message("Doxygen build started")

    # note the option ALL which allows to build the docs together with the application
    add_custom_target( docs COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )
else ()
  message(WARNING "Doxygen need to be installed to generate the doxygen documentation")
endif ()

if (NOT BUILD_ONLY_DOCS)
  add_subdirectory(src)
  add_subdirectory(tests)
endif ()

# add_subdirectory("${GRPC_SOURCE_DIR}/third_party/re2" EXCLUDE_FROM_ALL)