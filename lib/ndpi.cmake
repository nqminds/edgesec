if (BUILD_NDPI_LIB AND NOT (BUILD_ONLY_DOCS))
  add_compile_definitions(WITH_NDPI_SERVICE)
  set(LIBNDPI_PATH ${CMAKE_CURRENT_BINARY_DIR}/lib/ndpi)
  set(LIBNDPI_INCLUDE_PATH ${LIBNDPI_PATH}/include/ndpi)
  set(LIBNDPI_LIB_DIR "${LIBNDPI_PATH}/lib")

  find_library(LIBNDPI_LIB NAMES ndpi libndpi PATHS "${LIBNDPI_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBNDPI_LIB)
    message("Found libndpi library: ${LIBNDPI_LIB}")
  ELSE ()
      FetchContent_Declare(
        ndpi
        GIT_REPOSITORY https://github.com/ntop/nDPI
        GIT_TAG        3.4
      )
      set(FETCHCONTENT_QUIET OFF)
      FetchContent_MakeAvailable(ndpi)
      FetchContent_GetProperties(ndpi SOURCE_DIR NDPI_SOURCE_DIR)
      message("Source dir: ${NDPI_SOURCE_DIR}")
      execute_process(
        COMMAND ./autogen.sh
        WORKING_DIRECTORY "${NDPI_SOURCE_DIR}"
      )
      execute_process(
        COMMAND ./configure --prefix=${LIBNDPI_PATH}
        WORKING_DIRECTORY "${NDPI_SOURCE_DIR}"
      )
      execute_process(
        COMMAND make
        WORKING_DIRECTORY "${NDPI_SOURCE_DIR}"
      )
      execute_process(
        COMMAND make install
        WORKING_DIRECTORY "${NDPI_SOURCE_DIR}"
      )
    find_library(LIBNDPI_LIB NAMES ndpi libndpi PATHS "${LIBNDPI_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()
endif ()
