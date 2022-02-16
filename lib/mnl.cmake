# Compile libmnl library used for libnetlink
if (BUILD_MNL_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBMNL_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib/mnl")

  # Tell find_package(MNL) to search in local built mnl dir
  list(APPEND CMAKE_PREFIX_PATH ${LIBMNL_INSTALL_ROOT})
  if ((DEFINED MNL_INCLUDE_DIR) AND (DEFINED MNL_LIBRARY))
    find_package(MNL REQUIRED)
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
    find_package(MNL REQUIRED)
  endif ()
  message("Found libmnl library: ${MNL_LIBRARIES}")
elseif(NOT BUILD_ONLY_DOCS)
  # finding system install libmnl (e.g. installed via apt)
  find_package(MNL REQUIRED)
  message("Found libmnl library: ${MNL_LIBRARIES}")
endif ()
