cmake_minimum_required(VERSION 3.0.0)
project(EDGESEC C CXX)

include(CTest)
include(FetchContent)

# The edgesec version number.
set(EDGESEC_VERSION_MAJOR 0)
set(EDGESEC_VERSION_MINOR 1)
set(EDGESEC_VERSION_PATCH 0)

# The restsrv version number.
set(RESTSRV_VERSION_MAJOR 0)
set(RESTSRV_VERSION_MINOR 1)
set(RESTSRV_VERSION_PATCH 0)

# The capture version number.
set(CAPTURE_VERSION_MAJOR 0)
set(CAPTURE_VERSION_MINOR 1)
set(CAPTURE_VERSION_PATCH 0)

enable_testing()

# Find the hostapd program
find_program(HOSTAPD NAMES hostapd PATHS "${CMAKE_SOURCE_DIR}/build")
if (HOSTAPD)
  message("Found hostapd program: ${HOSTAPD}")
ELSE ()
  execute_process(COMMAND bash "${CMAKE_SOURCE_DIR}/lib/compile_hostap.sh")
endif ()

# Compile the cmocka library
set(CMOCKA_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/cmocka-1.1.5/include")
find_library(CMOCKA_LIB NAMES cmocka PATHS "${CMAKE_SOURCE_DIR}/lib/cmocka-1.1.5/build/src")
if (CMOCKA_LIB)
  message("Found cmocka library: ${CMOCKA_LIB}")
ELSE ()
  execute_process(COMMAND bash "${CMAKE_SOURCE_DIR}/lib/compile_cmocka.sh")
  find_library(CMOCKA_LIB NAMES cmocka PATHS "${CMAKE_SOURCE_DIR}/lib/cmocka-1.1.5/build/src")
endif ()

# Compile libmnl library used for libnetlink
find_library(LIBMNL_LIB NAMES mnl PATHS "${CMAKE_SOURCE_DIR}/lib/libmnl-1.0.4/build/lib")
if (LIBMNL_LIB)
  message("Found libmnl library: ${LIBMNL_LIB}")
ELSE ()
  execute_process(COMMAND bash "${CMAKE_SOURCE_DIR}/lib/compile_libmnl.sh")
endif ()

# Compile library libnetlink
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

# Compile libmicrohttpd-0.9.72
find_library(LIBMICROHTTPD_LIB NAMES microhttpd PATHS "${CMAKE_SOURCE_DIR}/lib/libmicrohttpd-0.9.72/build/lib")
set(LIBMICROHTTPD_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/libmicrohttpd-0.9.72/build/include")
if (LIBMICROHTTPD_LIB)
  message("Found libmicrohttpd library: ${LIBMICROHTTPD_LIB}")
ELSE ()
  execute_process(COMMAND bash "${CMAKE_SOURCE_DIR}/lib/compile_libmicrohttpd.sh")
  find_library(LIBMICROHTTPD_LIB NAMES microhttpd PATHS "${CMAKE_SOURCE_DIR}/lib/libmicrohttpd-0.9.72/build/lib")
endif ()

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

find_library(LIBPCAP_LIB NAMES pcap)
if (LIBPCAP_LIB)
  message("Found libpcap library: ${LIBPCAP_LIB}")
ELSE ()
  message(FATAL_ERROR "Could not find pcap library.")
endif ()

find_library(LIBSQLITE3_LIB NAMES sqlite3)
if (LIBSQLITE3_LIB)
  message("Found libsqlite3 library: ${LIBSQLITE3_LIB}")
ELSE ()
  message(FATAL_ERROR "Could not find libsqlite3 library.")
endif ()

# Compile libgrpc
FetchContent_Declare(
  gRPC
  GIT_REPOSITORY https://github.com/grpc/grpc
  GIT_TAG        v1.36.4  # e.g v1.28.0
)
set(FETCHCONTENT_QUIET OFF)
FetchContent_MakeAvailable(gRPC)
set(_PROTOBUF_LIBPROTOBUF libprotobuf)
set(_REFLECTION grpc++_reflection)
set(_PROTOBUF_PROTOC $<TARGET_FILE:protoc>)
set(_GRPC_GRPCPP grpc++)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)

get_filename_component(sqlite_proto "protos/sqlite_sync.proto" ABSOLUTE)
get_filename_component(sqlite_proto_path "${sqlite_proto}" PATH)

# Generated sources
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

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

add_library(sqlite_grpc_proto ${sqlite_grpc_srcs} ${sqlite_grpc_hdrs} ${sqlite_proto_srcs} ${sqlite_proto_hdrs})
target_link_libraries(sqlite_grpc_proto ${_GRPC_GRPCPP})

add_executable(hello hello.cc)
target_link_libraries(hello sqlite_grpc_proto ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

# find_library(LIBGRPC_LIB NAMES grpc PATHS "${CMAKE_SOURCE_DIR}/lib/grpc/cmake/build")
# set(LIBGRPC_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/grpc/cmake/build/include")
# if (LIBGRPC_LIB)
#   message("Found libgrpc library: ${LIBGRPC_LIB}")
# ELSE ()
#   execute_process(COMMAND bash "${CMAKE_SOURCE_DIR}/lib/compile_grpc.sh")
#   find_library(LIBGRPC_LIB NAMES grpc PATHS "${CMAKE_SOURCE_DIR}/lib/grpc/cmake/build")
# endif ()

# find_library(LIBGRPC++_REFLECTION_LIB NAMES grpc++_reflection PATHS "${CMAKE_SOURCE_DIR}/lib/grpc/cmake/build")
# if (LIBGRPC++_REFLECTION_LIB)
#   message("Found libgrpc++_reflection library: ${LIBGRPC++_REFLECTION_LIB}")
# ELSE ()
#   message(FATAL_ERROR "Could not find libgrpc++_reflection library.")
# endif ()

# find_library(LIBGRPC++_LIB NAMES grpc++ PATHS "${CMAKE_SOURCE_DIR}/lib/grpc/cmake/build")
# if (LIBGRPC++_LIB)
#   message("Found libgrpc++ library: ${LIBGRPC++_LIB}")
# ELSE ()
#   message(FATAL_ERROR "Could not find libgrpc++ library.")
# endif ()

# find_library(LIBPROTOBUF_LIB NAMES protoc libprotoc)
# if (LIBPROTOBUF_LIB)
#   message("Found libprotobuf library: ${LIBPROTOBUF_LIB}")
# ELSE ()
#   message(FATAL_ERROR "Could not find libprotobuf library.")
# endif ()

# C compiler options
set(CMAKE_BUILD_TYPE Debug)
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

#Compile protobufs
# find_program(PROTOC_CMD NAMES protoc)
# find_program(PLUGIN_CMD NAMES grpc_cpp_plugin HINTS "${CMAKE_SOURCE_DIR}/lib/grpc/cmake/build")

# if (PROTOC_CMD)
#   message("Found protoc binary: ${PROTOC_CMD}")
#   execute_process(COMMAND protoc --version OUTPUT_VARIABLE PROTOC_CHECK_CMD)
#   if (PROTOC_CHECK_CMD MATCHES "libprotoc.3")
#     message("Found correct version of libprotoc")
#     execute_process(COMMAND protoc -I "${CMAKE_SOURCE_DIR}/protos" --grpc_out=${CMAKE_SOURCE_DIR}/src/capture --plugin=protoc-gen-grpc=${PLUGIN_CMD} ${CMAKE_SOURCE_DIR}/protos/sqlite_sync.proto)
#     execute_process(COMMAND protoc -I "${CMAKE_SOURCE_DIR}/protos" --cpp_out=${CMAKE_SOURCE_DIR}/src/capture ${CMAKE_SOURCE_DIR}/protos/sqlite_sync.proto)
#   ELSE ()
#     message(FATAL_ERROR "wrong protoc version, needed >=3")
#   endif ()
# ELSE ()
#   message(FATAL_ERROR "protoc and grpc_cpp_plugin not found")
# endif ()

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

add_subdirectory(src)
add_subdirectory(tests)
