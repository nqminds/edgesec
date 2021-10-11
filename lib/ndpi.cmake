if (BUILD_NDPI_LIB AND NOT (BUILD_ONLY_DOCS))
  add_compile_definitions(WITH_NDPI_SERVICE)
  set(LIBNDPI_INSTALL_ROOT ${CMAKE_CURRENT_BINARY_DIR}/lib)
  set(LIBNDPI_INSTALL_DIR ${LIBNDPI_INSTALL_ROOT}/ndpi)
  set(LIBNDPI_INCLUDE_PATH ${LIBNDPI_INSTALL_DIR}/include/ndpi)
  set(LIBNDPI_LIB_DIR "${LIBNDPI_INSTALL_DIR}/lib")

  find_library(LIBNDPI_LIB NAMES ndpi libndpi PATHS "${LIBNDPI_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBNDPI_LIB)
    message("Found libndpi library: ${LIBNDPI_LIB}")
  ELSE ()
    FetchContent_Declare(
      ndpi_src
      URL https://github.com/ntop/nDPI/archive/refs/tags/4.0.tar.gz
    )
    FetchContent_Populate(ndpi_src)

    execute_process(COMMAND bash ${CMAKE_SOURCE_DIR}/lib/compile_ndpi.sh ${LIBNDPI_INSTALL_ROOT} ${ndpi_src_SOURCE_DIR})
    find_library(LIBNDPI_LIB NAMES ndpi libndpi PATHS "${LIBNDPI_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()
endif ()
