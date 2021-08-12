# Compile libmnl library used for libnetlink
if (BUILD_MNL_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBMNL_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/libmnl-1.0.4")
  set(LIBMNL_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib/mnl")
  set(LIBMNL_INCLUDE_DIR "${LIBMNL_INSTALL_DIR}/include")
  set(LIBMNL_LIB_DIR "${LIBMNL_INSTALL_DIR}/lib")

  find_library(LIBMNL_LIB NAMES mnl libmnl PATHS "${LIBMNL_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBMNL_LIB)
    message("Found libmnl library: ${LIBMNL_LIB}")
  ELSE ()
    execute_process(
      COMMAND autoreconf -f -i
      WORKING_DIRECTORY "${LIBSQLITE_SOURCE_DIR}"
    )

    execute_process(
      COMMAND ./configure --prefix=${LIBMNL_INSTALL_DIR}
      WORKING_DIRECTORY "${LIBMNL_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make
      WORKING_DIRECTORY "${LIBMNL_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make install
      WORKING_DIRECTORY "${LIBMNL_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make clean
      WORKING_DIRECTORY "${LIBMNL_SOURCE_DIR}"
    )

    find_library(LIBMNL_LIB NAMES mnl libmnl PATHS "${LIBMNL_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()
endif ()
