cmake_minimum_required(VERSION 3.0.0)
project(EDGESEC)

include(CTest)

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
find_program(HOSTAPD NAMES hostapd PATHS "${CMAKE_HOME_DIRECTORY}/build")
if (HOSTAPD)
  message("Found hostapd program: ${HOSTAPD}")
ELSE (HOSTAPD)
  execute_process(COMMAND bash "${CMAKE_HOME_DIRECTORY}/lib/compile_hostap.sh")
endif (HOSTAPD)

# Compile the cmocka library
set(CMOCKA_INCLUDE_DIR "${CMAKE_HOME_DIRECTORY}/lib/cmocka-1.1.5/include")
find_library(CMOCKA_LIB NAMES cmocka PATHS "${CMAKE_HOME_DIRECTORY}/lib/cmocka-1.1.5/build/src")
if (CMOCKA_LIB)
  message("Found cmocka library: ${CMOCKA_LIB}")
ELSE (CMOCKA_LIB)
  execute_process(COMMAND bash "${CMAKE_HOME_DIRECTORY}/lib/compile_cmocka.sh")
  find_library(CMOCKA_LIB NAMES cmocka PATHS "${CMAKE_HOME_DIRECTORY}/lib/cmocka-1.1.5/build/src")
endif (CMOCKA_LIB)

# Compile libmnl library used for libnetlink
find_library(LIBMNL_LIB NAMES mnl PATHS "${CMAKE_HOME_DIRECTORY}/lib/libmnl-1.0.4/build/lib")
if (LIBMNL_LIB)
  message("Found libmnl library: ${LIBMNL_LIB}")
ELSE (LIBMNL_LIB)
  execute_process(COMMAND bash "${CMAKE_HOME_DIRECTORY}/lib/compile_libmnl.sh")
endif (LIBMNL_LIB)

# Compile library libnetlink
set(LIBNETLINK_INCLUDE_DIR "${CMAKE_HOME_DIRECTORY}/lib/libnetlink/include")
set(LIBNETLINK_UAPI_INCLUDE_DIR "${CMAKE_HOME_DIRECTORY}/lib/libnetlink/include/uapi")
find_library(LIBNETLINK_LIB NAMES libnetlink PATHS "${CMAKE_HOME_DIRECTORY}/lib/libnetlink/build/lib")
if (LIBNETLINK_LIB)
  message("Found libnetlink library: ${LIBNETLINK_LIB}")
ELSE (LIBNETLINK_LIB)
  execute_process(COMMAND bash "${CMAKE_HOME_DIRECTORY}/lib/compile_libnetlink.sh")
  find_library(LIBNETLINK_LIB NAMES libnetlink PATHS "${CMAKE_HOME_DIRECTORY}/lib/libnetlink/build/lib")
endif (LIBNETLINK_LIB)
find_library(LL_MAP_LIB NAMES ll_map PATHS "${CMAKE_HOME_DIRECTORY}/lib/libnetlink/build/lib")
message("Found ll_map library: ${LL_MAP_LIB}")
find_library(UTILS_LIB NAMES utils PATHS "${CMAKE_HOME_DIRECTORY}/lib/libnetlink/build/lib")
message("Found utils library: ${UTILS_LIB}")
find_library(RT_NAMES_LIB NAMES rt_names PATHS "${CMAKE_HOME_DIRECTORY}/lib/libnetlink/build/lib")
message("Found rt_names library: ${RT_NAMES_LIB}")
find_library(LL_TYPES_LIB NAMES ll_types PATHS "${CMAKE_HOME_DIRECTORY}/lib/libnetlink/build/lib")
message("Found ll_types library: ${LL_TYPES_LIB}")
find_library(LL_PROTO_LIB NAMES ll_proto PATHS "${CMAKE_HOME_DIRECTORY}/lib/libnetlink/build/lib")
message("Found ll_types library: ${LL_PROTO_LIB}")

# Compilelinmicrohttpd-0.9.72
find_library(LIBMICROHTTPD_LIB NAMES microhttpd PATHS "${CMAKE_HOME_DIRECTORY}/lib/libmicrohttpd-0.9.72/build/lib")
set(LIBMICROHTTPD_INCLUDE_DIR "${CMAKE_HOME_DIRECTORY}/lib/libmicrohttpd-0.9.72/build/include")
if (LIBMICROHTTPD_LIB)
  message("Found libmicrohttpd library: ${LIBMICROHTTPD_LIB}")
ELSE (LIBMICROHTTPD_LIB)
  execute_process(COMMAND bash "${CMAKE_HOME_DIRECTORY}/lib/compile_libmicrohttpd.sh")
  find_library(LIBMICROHTTPD_LIB NAMES microhttpd PATHS "${CMAKE_HOME_DIRECTORY}/lib/libmicrohttpd-0.9.72/build/lib")
endif (LIBMICROHTTPD_LIB)


# C compiler options
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-variable")

# Set the color for terminal logging
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLOG_USE_COLOR")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG_LIBNL")


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

message("Searching for Linux netlink library")

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
endif (LibNL_INCLUDE_DIR AND LibNL_LIBRARY)

if (LibNL_FOUND)
	if (NOT LibNL_FIND_QUIETLY)
    message("Found netlink library: ${LibNL_LIBRARY}")
    # message("Found netlink route library: ${LibNL_ROUTE_LIBRARY}")
    # message("Found netlink netfilter library: ${LibNL_NETFILTER_LIBRARY}")
    message("Found netlink genl library: ${LibNL_GENL_LIBRARY}")
    message("Found netlink includes: ${LibNL_INCLUDE_DIR}")
	endif (NOT LibNL_FIND_QUIETLY)
ELSE (LibNL_FOUND)
	if (LibNL_FIND_REQUIRED)
		message("Netlink version 3 development packages cannot be found.")
		message("In Debian/Ubuntu, they may be called:")
		message("libnl-3-dev libnl-genl-3dev libnl-nf-3-dev libnl-route-3-dev")
		message(FATAL_ERROR "Could not find netlink library.")
	endif (LibNL_FIND_REQUIRED)
endif (LibNL_FOUND)

find_library(LIBPCAP_LIB NAMES pcap)
if (LIBPCAP_LIB)
  message("Found libpcap library: ${LIBPCAP_LIB}")
ELSE (LIBPCAP_LIB)
  message(FATAL_ERROR "Could not find pcap library.")
endif (LIBPCAP_LIB)


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
        WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )
else (DOXYGEN_FOUND)
  message(WARNING "Doxygen need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)

add_subdirectory(src)
add_subdirectory(tests)
