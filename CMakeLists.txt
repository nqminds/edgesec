cmake_minimum_required(VERSION 3.14.0) # required for FindSQLite3
cmake_policy(VERSION 3.14.0...3.24.0)

project(EDGESEC
  VERSION 0.1.0
  HOMEPAGE_URL "https://github.com/nqminds/edgesec"
  DESCRIPTION "Secure router - reference implementation"
  LANGUAGES C CXX
)
# CMake proposal for semver https://gitlab.kitware.com/cmake/cmake/-/issues/23649
set(PROJECT_VERSION_PRERELEASE alpha.0)

set(
  PROJECT_VERSION
  "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}"
)
if (NOT "${PROJECT_VERSION_PRERELEASE}" STREQUAL "")
  string(APPEND PROJECT_VERSION "-${PROJECT_VERSION_PRERELEASE}")
endif()

if ("${PROJECT_VERSION_BUILD_IDENTIFIER}" STREQUAL "")
  # try to load build ID from environment variables only if on a git branch
  # (we assume git tags are static and therefore build ids are not needed)
  if (NOT "$ENV{GITHUB_SHA}" STREQUAL "" AND "$ENV{GITHUB_REF_TYPE}" STREQUAL "branch")
    set(PROJECT_VERSION_BUILD_IDENTIFIER "sha.$ENV{GITHUB_SHA}")
  endif()
endif()

if (NOT "${PROJECT_VERSION_BUILD_IDENTIFIER}" STREQUAL "")
  string(APPEND PROJECT_VERSION "+${PROJECT_VERSION_BUILD_IDENTIFIER}")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/lib")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/docs")

include(AddCMockaTest)
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
option(BUILD_PROTOBUFC_LIB "Build protobuf-c library" ON)
option(BUILD_SQLHOOK "Build the sqlhook extension library" OFF)

option(USE_NETLINK_SERVICE "Use netlink service" OFF)
cmake_dependent_option(BUILD_MNL_LIB "Build mnl library" ON USE_NETLINK_SERVICE OFF)
cmake_dependent_option(BUILD_NETLINK_LIB "Build netlink library" ON USE_NETLINK_SERVICE OFF)

option(USE_UCI_SERVICE "Use OpenWRT uci service" OFF)
option(USE_RADIUS_SERVICE "Use RADIUS service" ON)
option(USE_MDNS_SERVICE "Use mDNS forwarder service" ON)
option(USE_CAPTURE_SERVICE "Use the capture service" ON)

# Capture middleware options
option(USE_CLEANER_MIDDLEWARE "Use the cleaner middleware" OFF)
option(USE_HEADER_MIDDLEWARE "Use the header middleware" OFF)
option(USE_PCAP_MIDDLEWARE "Use the pcap middleware" OFF)
option(USE_TAP_MIDDLEWARE "Use the tap middleware" OFF)
option(USE_PROTOBUF_MIDDLEWARE "Use the protobuf middleware" OFF)

cmake_dependent_option(BUILD_UCI_LIB "Build OpenWRT UCI library" ON USE_UCI_SERVICE OFF)
option(USE_GENERIC_IP_SERVICE "Use generic ip service" OFF)

option(USE_CRYPTO_SERVICE "Use the crypto service" OFF)
cmake_dependent_option(BUILD_OPENSSL_LIB "Build OpenSSL" ON USE_CRYPTO_SERVICE OFF)

option(USE_ZYMKEY4_HSM "Use the Zymkey4 HSM" OFF)
option(CONFIGURE_COVERAGE "Configure for code coverage (requires lcov)" OFF)

# Default ExternalProject download directory.
# Useful for two reasons:
#   - A single download directory can be shared for all build presets
#   - Allows building/configuring when there is no internet connection
#     (e.g. OpenWRT SDK or default `pdebuild` environment)
set(EP_DOWNLOAD_DIR "" CACHE PATH "ExternalProject default DOWNLOAD_DIR")

set(TRIPLET "${CMAKE_LIBRARY_ARCHITECTURE}" CACHE STRING "Target triplet to use for autoconf (e.g. output of `cc -dumpmachine`)")

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
  elseif (system_name STREQUAL "FreeBSD")
    set(${output_var} "freebsd" PARENT_SCOPE)
  else (system_name STREQUAL "Linux")
    message(FATAL_ERROR "'${system_name}' could not be converted to an autoconf os specifier")
  endif(system_name STREQUAL "Linux")
endfunction(get_autoconf_os)

get_autoconf_os(${CMAKE_HOST_SYSTEM_NAME} build_autoconf_os)
string(TOLOWER "${CMAKE_HOST_SYSTEM_PROCESSOR}-${build_autoconf_os}" build_autoconf_triple)
set(target_autoconf_triple "${TRIPLET}")

if (CMAKE_CROSSCOMPILING)
  message("Cross-compiling, setting cross-compiling autoconf/pkg-config vars")
  message("Build (autoconf --build) autoconf triple is ${build_autoconf_triple}")
  message("Target (autoconf --host) autoconf triple is ${TRIPLET}")
  if (target_autoconf_triple STREQUAL "")
    message(WARNING
      "edgesec is configured for cross-compiling, but could not detect a valid TRIPLET value."
      " This may cause issues when cross-compiling sqlite/other libs.")
  endif()

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
if("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
  # we use some BSD exclusive functions, and there is no easy way to opt-in
  # to this on FreeBSD
  # __BSD_VISIBLE might work, but is non-official
  set(CMAKE_C_EXTENSIONS ON)
else()
  # only use standard C and opt-in to non-standard includes
  set(CMAKE_C_EXTENSIONS OFF)
endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-variable -Wall -Wextra")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# use -std=c++11 rather than -std=gnu++11
set(CMAKE_CXX_EXTENSIONS OFF)

# sqlhook is a shared library that links to static libs, so -fPIC is needed
# todo: enable only for sqlhook dependencies
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Include the libraries
include(hostapd)
include(cmocka)
include(minIni)
include(mnl)
include(eloop)
include(netlink)
include(nl)
include(uuid)
include(pcap)
include(openssl)
include(sqlite)
include(zymkey4)
include(uci)
include(uthash)
include(protobuf-c)

# On Linux, creates a Threads::Threads target that points to pthread
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# Most C11 implementation support threads.h, but it's technically optional and not yet supported on MSVC
include(CheckIncludeFile)
check_include_file(threads.h C11_STD_THREADS)
if (NOT C11_STD_THREADS)
  message(FATAL_ERROR "Your C11 stdlib does not support #include <threads.h>, see https://en.cppreference.com/w/c/thread")
endif()

add_library(Threads::C11Threads INTERFACE IMPORTED)
if("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
  # FreeBSD has a seperate C11 threads library we need to link to
  set_target_properties(Threads::C11Threads PROPERTIES INTERFACE_LINK_LIBRARIES "stdthreads")
else()
  set_target_properties(Threads::C11Threads PROPERTIES INTERFACE_LINK_LIBRARIES Threads::Threads)
endif()

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
  if (USE_NETLINK_SERVICE AND USE_UCI_SERVICE AND USE_GENERIC_IP_SERVICE)
    message(FATAL_ERROR "Only USE_NETLINK_SERVICE or USE_UCI_SERVICE allowed.")
  endif ()
  if (USE_NETLINK_SERVICE)
    add_compile_definitions(WITH_NETLINK_SERVICE)
  elseif(USE_UCI_SERVICE)
    add_compile_definitions(WITH_UCI_SERVICE)
  elseif(USE_GENERIC_IP_SERVICE)
    add_compile_definitions(WITH_IP_GENERIC_SERVICE)
  else()
    message(FATAL_ERROR "You must define enable one of USE_NETLINK_SERVICE or USE_UCI_SERVICE or USE_GENERIC_IP_SERVICE.")
  endif()

  if (CMAKE_CROSSCOMPILING)
    # don't add test / code coverage when cross-compiling
    add_subdirectory(src)
  else ()
    if (CONFIGURE_COVERAGE)
      include(CodeCoverage)
      # enable before the src() flag to enable code coverage
      append_coverage_compiler_flags()

      include(ProcessorCount)
      ProcessorCount(PROCESSOR_COUNT)

      setup_target_for_coverage_lcov(
        NAME coverage
        EXECUTABLE ctest
        EXECUTABLE_ARGS --output-on-failure -j "${PROCESSOR_COUNT}"
        EXCLUDE
          "${PROJECT_SOURCE_DIR}/lib/*"
          # These files are only in the build/ directory, but
          # llvm-cov gcov doesn't seem to like it
          "${PROJECT_SOURCE_DIR}/middlewares_list.c"
          # The _deps/ folder is created by CMake's FetchContent
          "${PROJECT_SOURCE_DIR}/_deps/*"
      )
    endif()
    # src must be after codecoverage but before tests
    add_subdirectory(src)
    add_subdirectory(tests)
  endif ()

  include(install)
endif ()

add_custom_target(archive COMMAND
    ${CMAKE_COMMAND} -E tar "cvz" "${_project_lower}-${_sys}-${PROJECT_VERSION}.tar.gz" --format=gnutar "${CMAKE_INSTALL_PREFIX}")
