# Compile libmnl library used for libnetlink
if (BUILD_ONLY_DOCS OR NOT USE_NETLINK_SERVICE)
elseif(BUILD_MNL_LIB)
  set(LIBMNL_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib/mnl")

  ExternalProject_Add(
    libmnl_src
    URL https://www.netfilter.org/pub/libmnl/libmnl-1.0.4.tar.bz2
    URL_HASH SHA256=171f89699f286a5854b72b91d06e8f8e3683064c5901fb09d954a9ab6f551f81
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
    INSTALL_DIR "${LIBMNL_INSTALL_ROOT}"
    CONFIGURE_COMMAND autoreconf -f -i <SOURCE_DIR>
    COMMAND
      ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}"
      <SOURCE_DIR>/configure --prefix=<INSTALL_DIR> "--host=${CMAKE_LIBRARY_ARCHITECTURE}"
      # use position independent code, even for static lib, in case we want to make shared lib later
      --with-pic=on
      "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
    # need to manually specify PATH, so that make knows where to find cross-compiling GCC
    BUILD_COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" $(MAKE)
    INSTALL_COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" $(MAKE) install
  )

  ExternalProject_Get_Property(libmnl_src INSTALL_DIR)
  set(LIBMNLINSTALL_DIR "${INSTALL_DIR}")

  # set these variables so that find_package(MNL REQUIRED) works
  # when called later
  add_library(MNL::mnl SHARED IMPORTED)
  set(MNL_LIBRARY "${LIBMNLINSTALL_DIR}/lib/libmnl.so")
  set(MNL_INCLUDE_DIR "${LIBMNLINSTALL_DIR}/include")

  file(MAKE_DIRECTORY "${MNL_INCLUDE_DIR}")
    set_target_properties(MNL::mnl PROPERTIES
    IMPORTED_LOCATION "${LIBMNLINSTALL_DIR}/lib/libmnl.so"
    INTERFACE_INCLUDE_DIRECTORIES "${MNL_INCLUDE_DIR}"
  )
  add_dependencies(MNL::mnl libmnl_src)
else()
  # finding system install libmnl (e.g. installed via apt)
  find_package(MNL REQUIRED)
  message("Found libmnl library: ${MNL_LIBRARIES}")
endif()
