# Builds hostapd using ExternalProject

# v3.14.0+ is required by BUILD_IN_SOURCE + SOURCE_SUBDIR together
include(ExternalProject)

if (BUILD_ONLY_DOCS)
  return()
endif()

if (BUILD_HOSTAPD)
  set(HOSTAPD_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}")
  find_package(PkgConfig)
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
    hostapd_project
    URL
      https://w1.fi/releases/hostapd-2.10.tar.gz
      https://src.fedoraproject.org/repo/pkgs/hostapd/hostapd-2.10.tar.gz/sha512/243baa82d621f859d2507d8d5beb0ebda15a75548a62451dc9bca42717dcc8607adac49b354919a41d8257d16d07ac7268203a79750db0cfb34b51f80ff1ce8f/hostapd-2.10.tar.gz
    URL_HASH SHA512=243baa82d621f859d2507d8d5beb0ebda15a75548a62451dc9bca42717dcc8607adac49b354919a41d8257d16d07ac7268203a79750db0cfb34b51f80ff1ce8f
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
    INSTALL_DIR "${HOSTAPD_INSTALL_DIR}"
    BUILD_IN_SOURCE true
    SOURCE_SUBDIR "hostapd" # we only care about hostapd, not the entire hostap dir
    # copy over the configure file that contains our cross-compile settings
    CONFIGURE_COMMAND
      cmake -E copy
        "${CMAKE_CURRENT_BINARY_DIR}/hostapd.config"
        <BINARY_DIR>/.config
    INSTALL_COMMAND cmake -E copy <BINARY_DIR>/hostapd <INSTALL_DIR>/hostapd
    STEP_TARGETS download # may be used by hostapd_eap externalproject
  )
  set(HOSTAPD "${HOSTAPD_INSTALL_DIR}/hostapd")
endif (BUILD_HOSTAPD)

# Builds the hostapd::libeap library.
# See https://w1.fi/cgit/hostap/tree/eap_example?h=hostap_2_10
#
# This build process is kind of a mess, since we need to modify how hostapd
# builds this library, since by default it's not a seperate file
if (BUILD_HOSTAPD_EAP_LIB)
  set(LIBEAP_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib/libeap")

  configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/hostapd.config.in"
    "${CMAKE_CURRENT_BINARY_DIR}/hostapd-eap.config"
    @ONLY
  )

  if ("${CMAKE_GENERATOR}" MATCHES "Makefiles")
    set(MAKE_COMMAND "$(MAKE)") # recursive make (uses the same make as the main project)
  else()
    # just run make in a subprocess. We use single-process, but hostapd is a small project
    set(MAKE_COMMAND "make")
  endif ()

  set(EAPLIB_SOURCE_DIR "${hostapdsrc_SOURCE_DIR}/libeap")
  ExternalProject_Add(
      hostapd_libeap_project
      URL
        https://w1.fi/releases/hostapd-2.10.tar.gz
        https://src.fedoraproject.org/repo/pkgs/hostapd/hostapd-2.10.tar.gz/sha512/243baa82d621f859d2507d8d5beb0ebda15a75548a62451dc9bca42717dcc8607adac49b354919a41d8257d16d07ac7268203a79750db0cfb34b51f80ff1ce8f/hostapd-2.10.tar.gz
      URL_HASH SHA512=243baa82d621f859d2507d8d5beb0ebda15a75548a62451dc9bca42717dcc8607adac49b354919a41d8257d16d07ac7268203a79750db0cfb34b51f80ff1ce8f
      DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
      BUILD_IN_SOURCE true
      INSTALL_DIR "${LIBEAP_INSTALL_DIR}" # we have to set this in the `.config` file
      CONFIGURE_COMMAND
        COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/libeap
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_LIST_DIR}/libeap.mk" <SOURCE_DIR>/libeap/Makefile
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/hostapd-eap.config" <SOURCE_DIR>/libeap/.config
      BUILD_COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" "${MAKE_COMMAND}" -C <BINARY_DIR>/libeap
      INSTALL_COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" "${MAKE_COMMAND}" -C <BINARY_DIR>/libeap install
  )
  ExternalProject_Add_StepDependencies(
    hostapd_libeap_project
    configure
    "${CMAKE_CURRENT_LIST_DIR}/libeap.mk"
    "${CMAKE_CURRENT_BINARY_DIR}/hostapd-eap.config"
  )

  if (TARGET hostapd_project-download)
    # If we're building hostapdsrc, wait for it to download to prevent
    # a race-condition
    add_dependencies(hostapd_libeap_project hostapd_project-download)
  endif()

  # Hardcoded to be static, we can set CONFIG_SOLIB=yes in `.config` if we really want a shared-library
  set(LIBEAP_LIB "${LIBEAP_INSTALL_DIR}/lib/libeap.a")
  add_library(hostapd::libeap STATIC IMPORTED)

  set(LIBEAP_INCLUDE_DIRS "${LIBEAP_INSTALL_DIR}/include" "${LIBEAP_INSTALL_DIR}/include/utils")
  file(MAKE_DIRECTORY "${LIBEAP_INSTALL_DIR}/include" "${LIBEAP_INSTALL_DIR}/include/utils")

  set_target_properties(hostapd::libeap PROPERTIES
      IMPORTED_LOCATION "${LIBEAP_LIB}"
      INTERFACE_LINK_LIBRARIES OpenSSL3::Crypto
      INTERFACE_INCLUDE_DIRECTORIES "${LIBEAP_INCLUDE_DIRS}"
  )

  add_dependencies(hostapd::libeap hostapd_libeap_project)
endif (BUILD_HOSTAPD_EAP_LIB)
