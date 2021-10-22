# Compile libmnl library used for libnetlink
if (BUILD_MNL_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBMNL_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/libmnl-1.0.4")
  set(LIBMNL_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBMNL_INSTALL_DIR "${LIBMNL_INSTALL_ROOT}/mnl")
  set(LIBMNL_INCLUDE_DIR "${LIBMNL_INSTALL_DIR}/include")
  set(LIBMNL_LIB_DIR "${LIBMNL_INSTALL_DIR}/lib")

  find_library(LIBMNL_LIB NAMES mnl libmnl PATHS "${LIBMNL_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBMNL_LIB)
    message("Found libmnl library: ${LIBMNL_LIB}")
  ELSE ()
    message("Install MNL vars not set, compiling our own version")
    FetchContent_Declare(
      libmnl_src
      URL https://www.netfilter.org/pub/libmnl/libmnl-1.0.4.tar.bz2
      URL_HASH SHA256=171f89699f286a5854b72b91d06e8f8e3683064c5901fb09d954a9ab6f551f81
    )
    FetchContent_Populate(libmnl_src)

    execute_process(COMMAND
      bash
      ${CMAKE_SOURCE_DIR}/lib/compile_mnl.sh
      ${libmnl_src_SOURCE_DIR}
      ${LIBMNL_INSTALL_ROOT}
      ${target_autoconf_triple}
    )
    find_library(LIBMNL_LIB NAMES mnl libmnl PATHS "${LIBMNL_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()
endif ()
