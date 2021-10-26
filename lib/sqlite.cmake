# Compile libsqlite
if (BUILD_SQLITE_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBSQLITE_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBSQLITE_INSTALL_DIR "${LIBSQLITE_INSTALL_ROOT}/sqlite")
  set(LIBSQLITE_INCLUDE_DIR "${LIBSQLITE_INSTALL_DIR}/include")
  set(LIBSQLITE_LIB_DIR "${LIBSQLITE_INSTALL_DIR}/lib")

  find_library(LIBSQLITE_LIB NAMES sqlite3 libsqlite3 PATHS "${LIBSQLITE_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBSQLITE_LIB)
    message("Found libsqlite library: ${LIBSQLITE_LIB}")
  ELSE ()
    FetchContent_Declare(
      libsqlite
      URL https://www.sqlite.org/2021/sqlite-autoconf-3360000.tar.gz
      URL_HASH SHA256=bd90c3eb96bee996206b83be7065c9ce19aef38c3f4fb53073ada0d0b69bbce3
    )
    FetchContent_Populate(libsqlite)

    execute_process(COMMAND
      bash ${CMAKE_SOURCE_DIR}/lib/compile_sqlite.sh
      ${libsqlite_SOURCE_DIR}
      ${LIBSQLITE_INSTALL_ROOT}
      ${target_autoconf_triple}
    )
    find_library(LIBSQLITE_LIB NAMES sqlite3 libsqlite3 PATHS "${LIBSQLITE_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()
endif ()
