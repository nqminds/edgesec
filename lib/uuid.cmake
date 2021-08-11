# Compile libuuid-1.0.3
if (BUILD_UUID_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBUUID_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/libuuid-1.0.3")
  set(LIBUUID_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib/uuid")
  set(LIBUUID_INCLUDE_DIR "${LIBUUID_INSTALL_DIR}/include")
  set(LIBUUID_LIB_DIR "${LIBUUID_INSTALL_DIR}/lib")

  find_library(LIBUUID_LIB NAMES uuid libuuid PATHS "${LIBUUID_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBUUID_LIB)
    message("Found libuuid library: ${LIBUUID_LIB}")
  ELSE ()
    execute_process(
      COMMAND autoreconf -f -i
      WORKING_DIRECTORY "${LIBSQLITE_SOURCE_DIR}"
    )

    execute_process(
      COMMAND ./configure --prefix=${LIBUUID_INSTALL_DIR}
      WORKING_DIRECTORY "${LIBUUID_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make
      WORKING_DIRECTORY "${LIBUUID_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make install
      WORKING_DIRECTORY "${LIBUUID_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make clean
      WORKING_DIRECTORY "${LIBUUID_SOURCE_DIR}"
    )

    find_library(LIBUUID_LIB NAMES uuid libuuid PATHS "${LIBUUID_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()
endif ()
