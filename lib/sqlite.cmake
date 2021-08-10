# Compile libsqlite
if (BUILD_SQLITE_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBSQLITE_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/sqlite")
  set(LIBSQLITE_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib/sqlite")
  set(LIBSQLITE_INCLUDE_DIR "${LIBSQLITE_INSTALL_DIR}/include")
  set(LIBSQLITE_LIB_DIR "${LIBSQLITE_INSTALL_DIR}/lib")

  message ("INclude ${LIBSQLITE_INCLUDE_DIR}")
  find_library(LIBSQLITE_LIB NAMES sqlite3 libsqlite3 PATHS "${LIBSQLITE_LIB_DIR}")
  if (LIBSQLITE_LIB)
    message("Found libsqlite library: ${LIBSQLITE_LIB}")
  ELSE ()
    execute_process(
      COMMAND ./configure --prefix=${LIBSQLITE_INSTALL_DIR}
      WORKING_DIRECTORY "${LIBSQLITE_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make
      WORKING_DIRECTORY "${LIBSQLITE_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make install
      WORKING_DIRECTORY "${LIBSQLITE_SOURCE_DIR}"
    )

    execute_process(
      COMMAND make clean
      WORKING_DIRECTORY "${LIBSQLITE_SOURCE_DIR}"
    )

    find_library(LIBSQLITE_LIB NAMES sqlite3 libsqlite3 PATHS "${LIBSQLITE_LIB_DIR}")
  endif ()
endif ()
