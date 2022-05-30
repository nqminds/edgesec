# Builds hostapd using ExternalProject

# v3.14.0+ is required by BUILD_IN_SOURCE + SOURCE_SUBDIR together
cmake_minimum_required(VERSION 3.14.0)
include(ExternalProject)

if (BUILD_HOSTAPD AND NOT (BUILD_ONLY_DOCS))
  set(HOSTAPD_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/hostap")
  set(HOSTAPD_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}")

  include(FindPkgConfig)
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
    "${HOSTAPD_SOURCE_DIR}/hostapd/.config.in"
    "${CMAKE_CURRENT_BINARY_DIR}/hostapd.config"
    @ONLY
  )

  ExternalProject_Add(
    hostapd_externalproject
    URL "${HOSTAPD_SOURCE_DIR}"
    INSTALL_DIR "${HOSTAPD_INSTALL_DIR}"
    BUILD_IN_SOURCE true
    SOURCE_SUBDIR "hostapd" # we only care about hostapd, not the entire hostap dir
    # copy over the configure file that contains our cross
    CONFIGURE_COMMAND
      cmake -E copy
        "${CMAKE_CURRENT_BINARY_DIR}/hostapd.config"
        <BINARY_DIR>/.config
    INSTALL_COMMAND cmake -E copy <BINARY_DIR>/hostapd <INSTALL_DIR>/hostapd
  )
  set(HOSTAPD "${HOSTAPD_INSTALL_DIR}/hostapd")
endif ()
