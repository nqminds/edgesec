# Builds hostapd using ExternalProject

# v3.14.0+ is required by BUILD_IN_SOURCE + SOURCE_SUBDIR together
include(ExternalProject)

if (BUILD_HOSTAPD AND NOT (BUILD_ONLY_DOCS))
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
    "${CMAKE_CURRENT_LIST_DIR}/hostapd.config.in"
    "${CMAKE_CURRENT_BINARY_DIR}/hostapd.config"
    @ONLY
  )

  ExternalProject_Add(
    hostapd_externalproject
    URL https://w1.fi/releases/hostapd-2.10.tar.gz
    URL_HASH SHA512=243baa82d621f859d2507d8d5beb0ebda15a75548a62451dc9bca42717dcc8607adac49b354919a41d8257d16d07ac7268203a79750db0cfb34b51f80ff1ce8f
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
