# Compile libuuid-1.0.3
if (BUILD_UUID_LIB AND NOT (BUILD_ONLY_DOCS))

  set(LIBUUID_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBUUID_INSTALL_DIR "${LIBUUID_INSTALL_ROOT}/uuid")

  message("Will install libuuid into ${LIBUUID_INSTALL_DIR}")

  # ExternalProject downloads/builds/installs at **build** time
  # (e.g. during the `cmake --build` step)
  ExternalProject_Add(
    util_linux
    URL https://github.com/karelzak/util-linux/archive/refs/tags/v2.37.2.tar.gz
    URL_HASH SHA3_256=d45c2b0ef0cca67ef9cbac1099503564d559fa1c52c0335dfd119546624b6bd0
    CONFIGURE_COMMAND ./autogen.sh
    COMMAND ./configure
      --with-pic=yes # -fPIC required since we want to link our static lib to sqlhook shared lib
      --prefix=<INSTALL_DIR> --host=${target_autoconf_triple}
      --disable-all-programs --enable-libuuid
    BUILD_IN_SOURCE ON # not possible to build in seperate dir with autogen
    INSTALL_DIR "${LIBUUID_INSTALL_DIR}"
  )
  ExternalProject_Get_Property(util_linux INSTALL_DIR)

  set(LIBUUID_LIB_DIR "${INSTALL_DIR}/lib")
  set(LIBUUID_INCLUDE_DIR "${INSTALL_DIR}/include")

  add_library(util_linux::uuid STATIC IMPORTED)
  file(MAKE_DIRECTORY "${LIBUUID_INCLUDE_DIR}")
  set_target_properties(util_linux::uuid PROPERTIES
    IMPORTED_LOCATION "${LIBUUID_LIB_DIR}/libuuid.a"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBUUID_INCLUDE_DIR}"
  )
  add_dependencies(util_linux::uuid util_linux)
endif ()
