# Find the hostapd program
if (BUILD_HOSTAPD AND NOT (BUILD_ONLY_DOCS))
  include(ExternalProject)

  ExternalProject_Add(hostapd_external
    # the URL must be one that has both hostapd AND wpa_supplicant in it
    URL https://w1.fi/cgit/hostap/snapshot/hostap_2_9.tar.bz2
    # call custom script to configure hostapd
    CONFIGURE_COMMAND ${CMAKE_COMMAND}
      -D INSTALL_CONFIG=<SOURCE_DIR><SOURCE_SUBDIR>/.config
      -D CFLAGS="-I${LIBOPENSSL_INCLUDE_PATH}"
      -D LIBS="-L${LIBOPENSSL_LIB_PATH}"
      -D BINDIR="<INSTALL_DIR>/bin"
      -P ${CMAKE_CURRENT_LIST_DIR}/hostapd-configure.cmake
    BUILD_IN_SOURCE true
    SOURCE_SUBDIR "./hostapd" # does nothing since we're not configuring with cmake
  )
  ExternalProject_Get_Property(hostapd_external install_dir)
  set(HOSTAPD_INSTALL_DIR "${install_dir}")
  set(HOSTAPD "${HOSTAPD_INSTALL_DIR}/bin/hostapd")
endif ()
