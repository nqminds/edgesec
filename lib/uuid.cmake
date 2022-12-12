# Compile libuuid-1.0.3
if (BUILD_ONLY_DOCS)
  # pass
elseif (NOT BUILD_UUID_LIB)
  # finds LibUUID::LibUUID
  find_package(LibUUID MODULE REQUIRED)
endif()
if (BUILD_UUID_LIB AND NOT (BUILD_ONLY_DOCS))

  set(LIBUUID_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBUUID_INSTALL_DIR "${LIBUUID_INSTALL_ROOT}/uuid")

  message("Will install libuuid into ${LIBUUID_INSTALL_DIR}")

  if ("${CMAKE_GENERATOR}" MATCHES "Makefiles")
    set(MAKE_COMMAND "$(MAKE)") # recursive make (uses the same make as the main project)
  else()
    # just run make in a subprocess. We use single-process, but libmnl is a small project
    set(MAKE_COMMAND "make")
  endif ()

  set(UTIL_LINUX_VERSION 2.37.2)
  # ExternalProject downloads/builds/installs at **build** time
  # (e.g. during the `cmake --build` step)
  ExternalProject_Add(
    util_linux
    URL "https://github.com/karelzak/util-linux/archive/refs/tags/v${UTIL_LINUX_VERSION}.tar.gz"
    URL_HASH SHA3_256=d45c2b0ef0cca67ef9cbac1099503564d559fa1c52c0335dfd119546624b6bd0
    DOWNLOAD_NAME "util_linux-${UTIL_LINUX_VERSION}.tar.gz"
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
    CONFIGURE_COMMAND <SOURCE_DIR>/autogen.sh
    COMMAND
      ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" <SOURCE_DIR>/configure
      --with-pic=yes # -fPIC required since we want to link our static lib to sqlhook shared lib
      --prefix=<INSTALL_DIR>
      "--host=${target_autoconf_triple}"
      --disable-all-programs --enable-libuuid
      "CC=${CMAKE_C_COMPILER}"
    INSTALL_DIR "${LIBUUID_INSTALL_DIR}"
    # need to manually specify PATH, so that make knows where to find GCC
    BUILD_COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" "${MAKE_COMMAND}"
    INSTALL_COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" "${MAKE_COMMAND}" install
    # technically this is an INSTALL_BYPRODUCT, but we only ever need this to make Ninja happy
    BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libuuid.a"
  )
  ExternalProject_Get_Property(util_linux INSTALL_DIR)

  set(LIBUUID_LIB_DIR "${INSTALL_DIR}/lib")
  set(LIBUUID_INCLUDE_DIR "${INSTALL_DIR}/include")

  add_library(LibUUID::LibUUID STATIC IMPORTED)
  file(MAKE_DIRECTORY "${LIBUUID_INCLUDE_DIR}")
  set_target_properties(LibUUID::LibUUID PROPERTIES
    IMPORTED_LOCATION "${LIBUUID_LIB_DIR}/libuuid.a"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBUUID_INCLUDE_DIR}"
  )
  add_dependencies(LibUUID::LibUUID util_linux)
endif ()
