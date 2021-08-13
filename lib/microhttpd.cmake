# Compile libmicrohttpd-0.9.72
if (BUILD_MICROHTTPD_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBMICROHTTPD_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/libmicrohttpd-0.9.72")
  set(LIBMICROHTTPD_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib/libmicrohttpd")
  set(LIBMICROHTTPD_INCLUDE_DIR "${LIBMICROHTTPD_INSTALL_DIR}/include")
  set(LIBMICROHTTPD_LIB_DIR "${LIBMICROHTTPD_INSTALL_DIR}/lib")

  find_library(LIBMICROHTTPD_LIB NAMES microhttpd PATHS "${LIBMICROHTTPD_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBMICROHTTPD_LIB)
    message("Found libmicrohttpd library: ${LIBMICROHTTPD_LIB}")
  ELSE ()

    execute_process(
      COMMAND autoreconf -f -i
      WORKING_DIRECTORY "${LIBMICROHTTPD_SOURCE_DIR}"
    )

    execute_process(
      COMMAND ./configure --prefix=${LIBMICROHTTPD_INSTALL_DIR} --host=${COMPILE_CONFIG_HOST}
      WORKING_DIRECTORY "${LIBMICROHTTPD_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make
      WORKING_DIRECTORY "${LIBMICROHTTPD_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make install
      WORKING_DIRECTORY "${LIBMICROHTTPD_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make clean
      WORKING_DIRECTORY "${LIBMICROHTTPD_SOURCE_DIR}"
    )

    find_library(LIBMICROHTTPD_LIB NAMES microhttpd PATHS "${LIBMICROHTTPD_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()
endif ()
