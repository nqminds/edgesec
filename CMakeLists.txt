cmake_minimum_required(VERSION 3.14.0) # required by lib/sqlite.cmake

project(EDGESEC C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/lib")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/docs")

include(CTest)
include(FetchContent)
include(ExternalProject)
include(CMakeDependentOption)


string(TOLOWER ${CMAKE_HOST_SYSTEM_PROCESSOR} _sys)
string(TOLOWER ${PROJECT_NAME} _project_lower)

include(EdgesecInstallLocations)

# Installation options
# Only overwrite CMAKE_INSTALL_PREFIX if there is no -DCMAKE_INSTALL_PREFIX
IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "${PROJECT_BINARY_DIR}/${_project_lower}-dist" CACHE PATH "Installation path" FORCE)
ENDIF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

# RPATH must be set before defining targets
# $ORIGIN is so that shared libs can view other shared libs (e.g. libgrpc++ can see libxxx)
# $ORIGIN/lib is to support where we used to store shared libs
# ${EDGESEC_full_private_lib_dir} is where private shared libs will be stored after `make install`
file(
  RELATIVE_PATH
  "EDGESec_relative_private_lib_dir"
  ${CMAKE_INSTALL_FULL_BINDIR} ${EDGESEC_full_private_lib_dir}
)
message("Adding RPATH $ORIGIN relative path to: ${EDGESec_relative_private_lib_dir}")
set(
  CMAKE_INSTALL_RPATH
  "$ORIGIN" "$ORIGIN/lib" "${EDGESEC_full_private_lib_dir}"
  "$ORIGIN/${EDGESec_relative_private_lib_dir}"
)

option(BUILD_ONLY_DOCS "Build only docs" OFF)
option(BUILD_HOSTAPD "Build hostapd" OFF)
option(BUILD_SQLITE_LIB "Build sqlite3 library" ON)
option(BUILD_CMOCKA_LIB "Build cmocka library" OFF)
option(BUILD_UUID_LIB "Build uuid library" ON)
option(BUILD_PCAP_LIB "Build pcap library" ON)

option(USE_NETLINK_SERVICE "Use netlink service" OFF)
cmake_dependent_option(BUILD_MNL_LIB "Build mnl library" ON USE_NETLINK_SERVICE OFF)
cmake_dependent_option(BUILD_NETLINK_LIB "Build netlink library" ON USE_NETLINK_SERVICE OFF)

option(USE_UCI_SERVICE "Use OpenWRT uci service" OFF)
option(USE_RADIUS_SERVICE "Use mDNS forwarder service" ON)
option(USE_MDNS_SERVICE "Use mDNS forwarder service" ON)
option(USE_CAPTURE_SERVICE "Use the capture service" ON)

# Capture middleware options
option(USE_CLEANER_MIDDLEWARE "Use the cleaner middleware" OFF)
option(USE_HEADER_MIDDLEWARE "Use the header middleware" OFF)
option(USE_PCAP_MIDDLEWARE "Use the pcap middleware" OFF)

cmake_dependent_option(BUILD_UCI_LIB "Build OpenWRT UCI library" ON USE_UCI_SERVICE OFF)
option(USE_GENERIC_IP_SERVICE "Use generic ip service" OFF)
if (USE_NETLINK_SERVICE AND USE_UCI_SERVICE AND USE_GENERIC_IP_SERVICE)
  message(FATAL_ERROR "Only USE_NETLINK_SERVICE or USE_UCI_SERVICE allowed.")
endif ()

option(USE_CRYPTO_SERVICE "Use the crypto service" OFF)
cmake_dependent_option(BUILD_OPENSSL_LIB "Build OpenSSL" ON USE_CRYPTO_SERVICE OFF)
if (USE_CRYPTO_SERVICE)
  add_compile_definitions(TEST_CRYPTO_SERVICE_KEY="12345")
endif ()

option(USE_ZYMKEY4_HSM "Use the Zymkey4 HSM" OFF)

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'Debug' as none was specified.")
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()

# Convert CMAKE_SYSTEM_NAME to os specifier that autoconf understands
function(get_autoconf_os system_name output_var)
  if (system_name STREQUAL "Linux")
    set(${output_var} "linux-gnu" PARENT_SCOPE)
  else (system_name STREQUAL "Linux")
    message(FATAL_ERROR "'$system_name' could not be converted to an autoconf os specifier")
  endif(system_name STREQUAL "Linux")
endfunction(get_autoconf_os)

get_autoconf_os(${CMAKE_HOST_SYSTEM_NAME} build_autoconf_os)
string(TOLOWER "${CMAKE_HOST_SYSTEM_PROCESSOR}-${build_autoconf_os}" build_autoconf_triple)
set(target_autoconf_triple "${CMAKE_LIBRARY_ARCHITECTURE}")

if (CMAKE_CROSSCOMPILING)
  message("Cross-compiling, setting cross-compiling autoconf/pkg-config vars")
  message("Build (autoconf --build) autoconf triple is ${build_autoconf_triple}")
  message("Target (autoconf --host) autoconf triple is ${CMAKE_LIBRARY_ARCHITECTURE}")
  # tell PKG_CONFIG (required by hostap) to search correct folders when cross-compiling
  set(ENV{PKG_CONFIG_LIBDIR} "/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}/pkgconfig:/usr/share/pkgconfig")
  message("Setting cross-compiling PKG_CONFIG_LIBDIR to $ENV{PKG_CONFIG_LIBDIR}")
else(CMAKE_CROSSCOMPILING)
  # unset so that sqlite.cmake and etc. do not activate this
  unset(target_autoconf_triple)
endif(CMAKE_CROSSCOMPILING)

# currenty doesn't work if on, due to cyclical dependencies
set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "Build shared libraries")

# C compiler options
set(CMAKE_C_STANDARD 11) # we use C11 raw-strings
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_C_EXTENSIONS ON) # We use GNU C specific features
set(CMAKE_C_FLAGS "-Wunused-variable -Wall -Wextra")

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftest-coverage")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG_LIBNL")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# use -std=c++11 rather than -std=gnu++11
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
# hostapd and libnetlink relies on GNU specific features, like strncasecmp
set(CMAKE_C_EXTENSIONS ON)

# sqlhook is a shared library that links to static libs, so -fPIC is needed
# todo: enable only for sqlhook dependencies
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# The edgesec version number.
set(EDGESEC_VERSION_MAJOR 0)
set(EDGESEC_VERSION_MINOR 9)
set(EDGESEC_VERSION_PATCH 9)

# Include the libraries
include(hostapd)
include(cmocka)
include(mnl)
include(netlink)
include(nl)
include(uuid)
include(pcap)
include(openssl)
include(sqlite)
include(zymkey4)
include(uci)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file(
  "version.h.in"
  "${PROJECT_BINARY_DIR}/version.h"
)

# Copy the default configuration file to the build folder
# This config file is for development, not for `make install` use
configure_file(
  "dev-config.ini"
  "${PROJECT_BINARY_DIR}/dev-config.ini"
  COPYONLY # does not edit the file
)

include(doxygen)

if (NOT BUILD_ONLY_DOCS)
  add_subdirectory(src)
  if (NOT CMAKE_CROSSCOMPILING)
    add_subdirectory(tests)
  endif ()
  include(install)
endif ()

add_custom_target(archive COMMAND
    ${CMAKE_COMMAND} -E tar "cvz" "${_project_lower}-${_sys}-${EDGESEC_VERSION_MAJOR}.${EDGESEC_VERSION_MINOR}.${EDGESEC_VERSION_PATCH}.tar.gz" --format=gnutar "${CMAKE_INSTALL_PREFIX}")
