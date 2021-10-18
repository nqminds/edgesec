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
    execute_process(COMMAND
      bash
      ${CMAKE_SOURCE_DIR}/lib/compile_mnl.sh
      ${LIBMNL_SOURCE_DIR}
      ${LIBMNL_INSTALL_ROOT}
      ${target_autoconf_triple}
    )
    find_library(LIBMNL_LIB NAMES mnl libmnl PATHS "${LIBMNL_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()
endif ()
