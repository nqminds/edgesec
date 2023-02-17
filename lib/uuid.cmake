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

  # util-unix uses SOLIB_LDFLAGS as libtool flags for linking
  set(SOLIB_LDFLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
  if (CMAKE_CROSSCOMPILING AND "${CMAKE_C_COMPILER_ID}" MATCHES "Clang")
    # util-linux links with libtool
    # unfortunately, libtool ignores the `-target=...` parameter in it's flags,
    # which breaks cross-compiling for CheriBSD using cheribuild.
    # We can specify `-XCClinker` to force libtool to pass the value to the
    # underlying clang linker command.
    list(APPEND SOLIB_LDFLAGS "-XCClinker --target=${target_autoconf_triple}")
  endif()
  list(JOIN SOLIB_LDFLAGS " " SOLIB_LDFLAGS)

  # ExternalProject downloads/builds/installs at **build** time
  # (e.g. during the `cmake --build` step)
  ExternalProject_Add(
    util_linux
    URL "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.37/util-linux-2.37.2.tar.xz"
    URL_HASH SHA256=6a0764c1aae7fb607ef8a6dd2c0f6c47d5e5fd27aa08820abaad9ec14e28e9d9
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
    CONFIGURE_COMMAND <SOURCE_DIR>/autogen.sh
    COMMAND
      ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" <SOURCE_DIR>/configure
      --with-pic=yes # -fPIC required since we want to link our static lib to sqlhook shared lib
      --prefix=<INSTALL_DIR>
      "--host=${target_autoconf_triple}"
      --disable-all-programs --enable-libuuid
      "CC=${CMAKE_C_COMPILER}" "CFLAGS=${CMAKE_C_FLAGS}" "LDFLAGS=${CMAKE_SHARED_LINKER_FLAGS}"
      "SOLIB_LDFLAGS=${SOLIB_LDFLAGS}" # util-linux uses a custom ldflags for linking
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
