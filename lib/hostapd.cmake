# Builds hostapd using ExternalProject

# v3.14.0+ is required by BUILD_IN_SOURCE + SOURCE_SUBDIR together
include(ExternalProject)

set(HOSTAPD_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}")
set(LIBEAP_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(LIBEAP_INSTALL_DIR "${LIBEAP_INSTALL_ROOT}/libeap")
set(LIBEAP_INCLUDE_DIR "${LIBEAP_INSTALL_DIR}/include")
set(LIBEAP_LIB_DIR "${LIBEAP_INSTALL_DIR}/lib")

if ((BUILD_HOSTAPD OR BUILD_EAP_LIB) AND NOT (BUILD_ONLY_DOCS))
  if ("${CMAKE_GENERATOR}" MATCHES "Makefiles")
    set(MAKE_COMMAND "$(MAKE)") # recursive make (uses the same make as the main project)
  else()
    set(MAKE_COMMAND "make")
  endif ()

  if (NOT PKG_CONFIG_FOUND)
    message(FATAL_ERROR "pkg-config is required to build hostapd, but could not be found")
  endif()

  if (CMAKE_CROSSCOMPILING)
    message(
      WARNING
      "hostapd.cmake may not work correctly when cross-compiling. "
      "Please disable BUILD_HOSTAPD in your cmake config to skip compiling hostapd."
    )
  endif()

  configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/hostapd.config.in"
    "${CMAKE_CURRENT_BINARY_DIR}/hostapd.config"
    @ONLY
  )

  configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/eap.Makefile.in"
    "${CMAKE_CURRENT_BINARY_DIR}/eap.Makefile"
    @ONLY
  )

  FetchContent_Declare(hostapdsrc
    URL https://w1.fi/releases/hostapd-2.10.tar.gz
    URL_HASH SHA512=243baa82d621f859d2507d8d5beb0ebda15a75548a62451dc9bca42717dcc8607adac49b354919a41d8257d16d07ac7268203a79750db0cfb34b51f80ff1ce8f
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
  )
  FetchContent_MakeAvailable(hostapdsrc)
endif ()

if (BUILD_HOSTAPD AND NOT (BUILD_ONLY_DOCS))
  ExternalProject_Add(
    hostapd_project
    SOURCE_DIR ${hostapdsrc_SOURCE_DIR}
    INSTALL_DIR "${HOSTAPD_INSTALL_DIR}"
    BUILD_IN_SOURCE true
    SOURCE_SUBDIR "hostapd" # we only care about hostapd, not the entire hostap dir
    # copy over the configure file that contains our cross-compile settings
    CONFIGURE_COMMAND
      cmake -E copy
        "${CMAKE_CURRENT_BINARY_DIR}/hostapd.config"
        <BINARY_DIR>/.config
    INSTALL_COMMAND cmake -E copy <BINARY_DIR>/hostapd <INSTALL_DIR>/hostapd
  )
  set(HOSTAPD "${HOSTAPD_INSTALL_DIR}/hostapd")
endif ()

if (BUILD_EAP_LIB AND NOT (BUILD_ONLY_DOCS))
  file(MAKE_DIRECTORY "${LIBEAP_INCLUDE_DIR}")
  file(MAKE_DIRECTORY "${LIBEAP_INCLUDE_DIR}/utils")

  set(LIBEAP_LIB "${LIBEAP_INSTALL_DIR}/lib/libeap.a")
  add_library(hostapd::libeap STATIC IMPORTED)

  set(EAPLIB_SOURCE_DIR "${hostapdsrc_SOURCE_DIR}/eaplib")
  ExternalProject_Add(
      libeap_project
      SOURCE_DIR ${hostapdsrc_SOURCE_DIR}
      INSTALL_DIR ${LIBEAP_INSTALL_DIR}
      BUILD_IN_SOURCE true
      CONFIGURE_COMMAND
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/eap.Makefile <SOURCE_DIR>/Makefile
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/hostapd.config" <SOURCE_DIR>/.config
      BUILD_COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" "${MAKE_COMMAND}"
      INSTALL_COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" "${MAKE_COMMAND}" install
  )

  set(LIBEAP_INTERFACE_DIRS "${LIBEAP_INCLUDE_DIR}" "${LIBEAP_INCLUDE_DIR}/utils")
  set_target_properties(libeap::libeap PROPERTIES
      IMPORTED_LOCATION "${LIBEAP_LIB}"
      INTERFACE_LINK_LIBRARIES OpenSSL::Crypto
      INTERFACE_INCLUDE_DIRECTORIES "${LIBEAP_INTERFACE_DIRS}"
  )

  add_dependencies(libeap::libeap libeap_project)
endif ()
