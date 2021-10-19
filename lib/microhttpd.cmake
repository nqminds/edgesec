# Compile libmicrohttpd-0.9.72
if (BUILD_MICROHTTPD_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBMICROHTTPD_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBMICROHTTPD_INSTALL_DIR "${LIBMICROHTTPD_INSTALL_ROOT}/libmicrohttpd")
  set(LIBMICROHTTPD_INCLUDE_DIR "${LIBMICROHTTPD_INSTALL_DIR}/include")
  set(LIBMICROHTTPD_LIB_DIR "${LIBMICROHTTPD_INSTALL_DIR}/lib")

  find_library(LIBMICROHTTPD_LIB NAMES microhttpd PATHS "${LIBMICROHTTPD_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBMICROHTTPD_LIB)
    message("Found libmicrohttpd library: ${LIBMICROHTTPD_LIB}")
  ELSE ()
    FetchContent_Declare(
      microhttpd_src
      URL https://ftpmirror.gnu.org/libmicrohttpd/libmicrohttpd-0.9.72.tar.gz
      URL_HASH SHA256=0ae825f8e0d7f41201fd44a0df1cf454c1cb0bc50fe9d59c26552260264c2ff8
    )
    FetchContent_Populate(microhttpd_src)

    execute_process(COMMAND
      bash ${CMAKE_SOURCE_DIR}/lib/compile_microhttpd.sh
      ${microhttpd_src_SOURCE_DIR}
      ${LIBMICROHTTPD_INSTALL_ROOT}
      ${target_autoconf_triple}
    )
    find_library(LIBMICROHTTPD_LIB NAMES microhttpd PATHS "${LIBMICROHTTPD_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()
endif ()
