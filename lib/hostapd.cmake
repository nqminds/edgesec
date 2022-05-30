# Builds hostapd using ExternalProject

# v3.14.0+ is required by BUILD_IN_SOURCE + SOURCE_SUBDIR together
cmake_minimum_required(VERSION 3.14.0)
include(ExternalProject)

if (BUILD_HOSTAPD AND NOT (BUILD_ONLY_DOCS))
  set(HOSTAPD_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/hostap")
  set(HOSTAPD_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}")

  if (CMAKE_CROSSCOMPILING)
    message(
      FATAL_ERROR
      "hostapd.cmake currently does not support cross-compiling. "
      "Please disable BUILD_HOSTAPD in your cmake config to skip compiling hostapd."
    )
  endif()

  ExternalProject_Add(
    hostapd_externalproject
    URL "${HOSTAPD_SOURCE_DIR}"
    INSTALL_DIR "${HOSTAPD_INSTALL_DIR}"
    BUILD_IN_SOURCE true
    SOURCE_SUBDIR "hostapd" # we only care about hostapd, not the entire hostap dir
    CONFIGURE_COMMAND "" # no configure command
    INSTALL_COMMAND cmake -E copy <BINARY_DIR>/hostapd <INSTALL_DIR>/hostapd
  )
  set(HOSTAPD "${HOSTAPD_INSTALL_DIR}/hostapd")
endif ()
